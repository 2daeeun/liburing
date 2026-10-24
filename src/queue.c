/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200112L

#include "lib.h"
#include "syscall.h"
#include "liburing.h"
#include "int_flags.h"
#include "liburing/sanitize.h"
#include "liburing/io_uring.h"

_Static_assert(INT_FLAG_SPARE_PULL == LIBURING_INT_FLAG_SPARE_PULL,
	       "public and internal spare pull flags must match");
_Static_assert(sizeof(struct io_uring_spare_reg) == 56,
	       "spare registration ABI size");
_Static_assert(offsetof(struct io_uring_spare_reg, rescue_us) == 48 &&
	       offsetof(struct io_uring_spare_reg, features) == 52,
	       "spare registration ABI offsets");
_Static_assert(sizeof(struct io_uring_spare_debug) == 32,
	       "spare debug ABI size");

static bool spare_fsize_infinite;

void __io_uring_spare_init(void)
{
	struct rlimit rlim;
	bool infinite = !__sys_getrlimit(RLIMIT_FSIZE, &rlim) &&
			rlim.rlim_cur == RLIM_INFINITY;

	/*
	 * Sample once at registration, rather than on every submission. A later
	 * setrlimit only costs an extra enter: the kernel hands the lease back
	 * at an ineligible write and sets TASKRUN. Concurrent ring registrations
	 * may refresh this process-wide hint, so access it atomically.
	 */
	__atomic_store_n(&spare_fsize_infinite, infinite, __ATOMIC_RELAXED);
}

static bool spare_sq_eligible(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned head = io_uring_smp_load_acquire(sq->khead);
	unsigned tail = sq->sqe_tail;
	unsigned i;

	/* Pull registrations require NO_SQARRAY. Include short-submit leftovers. */
	for (i = head; i != tail; i++) {
		const struct io_uring_sqe *sqe = &sq->sqes[i & sq->ring_mask];

		switch (sqe->opcode) {
		case IORING_OP_WRITE:
		case IORING_OP_WRITE_FIXED:
			if (!__atomic_load_n(&spare_fsize_infinite, __ATOMIC_RELAXED))
				return false;
			/* fall through */
		case IORING_OP_READ:
		case IORING_OP_READ_FIXED:
			break;
		default:
			return false;
		}
		/* The kernel's table (io_spare_eligible(), io_exec_pull_alloc()). */
		if ((sqe->flags & ~(IOSQE_FIXED_FILE | IOSQE_ASYNC)) ||
		    sqe->personality || sqe->attr_ptr || sqe->attr_type_mask ||
		    sqe->off == (__u64) -1)
			return false;
	}
	return true;
}

static bool spare_pull_skip(struct io_uring *ring, unsigned submitted)
{
	unsigned kf;

	/* Publish tail before observing the lease (paired with kernel handback). */
	io_uring_smp_mb();
	kf = IO_URING_READ_ONCE(*ring->sq.kflags);
	/*
	 * IORING_SQ_TASKRUN only asks the owner to enter and run task_work. The
	 * callers do that with to_submit = 0 (cq_ring_needs_enter()), which keeps
	 * the lease; entering with the SQEs would make the kernel take the lease
	 * over on every batch (SpareRing perf round 1: 474k takeovers / 526k
	 * acquisitions in 30 s). Only an overflowed CQ forces a full enter.
	 */
	return submitted && (kf & IORING_SQ_LEASED) &&
		!(kf & IORING_SQ_CQ_OVERFLOW) &&
		io_uring_sq_space_left(ring) && spare_sq_eligible(ring);
}

/*
 * Returns true if we're not using SQ thread (thus nobody submits but us)
 * or if IORING_SQ_NEED_WAKEUP is set, so submit thread must be explicitly
 * awakened. For the latter case, we set the thread wakeup flag.
 * If no SQEs are ready for submission, returns false.
 */
static inline bool sq_ring_needs_enter(struct io_uring *ring,
				       unsigned submit,
				       unsigned *flags)
{
	if (!submit)
		return false;

	if (!(ring->flags & IORING_SETUP_SQPOLL))
		return true;

	/*
	 * Ensure the kernel can see the store to the SQ tail before we read
	 * the flags.
	 */
	io_uring_smp_mb();

	if (uring_unlikely(IO_URING_READ_ONCE(*ring->sq.kflags) &
			   IORING_SQ_NEED_WAKEUP)) {
		*flags |= IORING_ENTER_SQ_WAKEUP;
		return true;
	}

	return false;
}

static inline bool cq_ring_needs_flush(struct io_uring *ring)
{
	return IO_URING_READ_ONCE(*ring->sq.kflags) &
				 (IORING_SQ_CQ_OVERFLOW | IORING_SQ_TASKRUN);
}

static inline bool cq_ring_needs_enter(struct io_uring *ring)
{
	return (ring->int_flags & INT_FLAG_CQ_ENTER) || cq_ring_needs_flush(ring);
}

struct get_data {
	unsigned submit;
	unsigned wait_nr;
	unsigned get_flags;
	int sz;
	int has_ts;
	void *arg;
};

static int _io_uring_get_cqe(struct io_uring *ring,
			     struct io_uring_cqe **cqe_ptr,
			     struct get_data *data)
{
	struct io_uring_cqe *cqe = NULL;
	bool looped = false;
	int err = 0;

	do {
		bool need_enter = false;
		bool pull_skip;
		unsigned flags = ring_enter_flags(ring);
		unsigned nr_available;
		int ret;

		ret = __io_uring_peek_cqe(ring, &cqe, &nr_available);
		if (ret) {
			if (!err)
				err = ret;
			break;
		}
		if (!cqe && !data->wait_nr && !data->submit) {
			/*
			 * If we already looped once, we already entered
			 * the kernel. Since there's nothing to submit or
			 * wait for, don't keep retrying.
			 */
			if (looped || !cq_ring_needs_enter(ring)) {
				if (!err)
					err = -EAGAIN;
				break;
			}
			need_enter = true;
		}
		if (data->wait_nr > nr_available || need_enter) {
			flags |= IORING_ENTER_GETEVENTS | data->get_flags;
			need_enter = true;
		}
		pull_skip = (ring->int_flags & INT_FLAG_SPARE_PULL) &&
			    spare_pull_skip(ring, data->submit);
		if (!pull_skip && sq_ring_needs_enter(ring, data->submit, &flags))
			need_enter = true;
		if (!need_enter) {
			if (pull_skip) {
				if (!looped)
					err = data->submit;
				data->submit = 0;
			}
			break;
		}
		if (looped && data->has_ts) {
			/*
			 * When IORING_ENTER_EXT_ARG_REG is set, data->arg
			 * carries a register-wait offset (an integer), not a
			 * pointer to io_uring_getevents_arg.  Dereferencing it
			 * as a struct pointer causes a memory access violation.
			 * For the registered-wait path the kernel enforces the
			 * timeout, so treat any timeout the same as -ETIME here.
			 */
			if (data->get_flags & IORING_ENTER_EXT_ARG_REG) {
				if (!cqe && !err)
					err = -ETIME;
			} else {
				struct io_uring_getevents_arg *arg = data->arg;

				if (!cqe && arg->ts && !err)
					err = -ETIME;
			}
			break;
		}

		ret = __sys_io_uring_enter2(ring->enter_ring_fd,
					    pull_skip ? 0 : data->submit,
					    data->wait_nr, flags, data->arg,
					    data->sz);
		if (ret < 0) {
			if (!err)
				err = ret;
			break;
		}

		if (pull_skip) {
			/* A zero-submit GETEVENTS enter does not report pulled SQEs. */
			ret = data->submit;
			data->submit = 0;
		} else {
			data->submit -= ret;
		}
		if ((ring->int_flags & INT_FLAG_SPARE_PULL) && !looped)
			err = ret;
		if (cqe)
			break;
		if (!looped) {
			looped = true;
			err = ret;
		}
	} while (1);

	*cqe_ptr = cqe;
	return err;
}

int __io_uring_get_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr,
		       unsigned submit, unsigned wait_nr, sigset_t *sigmask)
{
	struct get_data data = {
		.submit		= submit,
		.wait_nr 	= wait_nr,
		.get_flags	= 0,
		.sz		= _NSIG / 8,
		.arg		= sigmask,
	};

	return _io_uring_get_cqe(ring, cqe_ptr, &data);
}

int io_uring_get_events(struct io_uring *ring)
{
	int flags = IORING_ENTER_GETEVENTS | ring_enter_flags(ring);

	return __sys_io_uring_enter(ring->enter_ring_fd, 0, 0, flags, NULL);
}

static inline bool io_uring_peek_batch_cqe_(struct io_uring *ring,
					    struct io_uring_cqe **cqes,
					    unsigned *count)
{
	unsigned ready = io_uring_cq_ready(ring);
	unsigned head;
	unsigned mask;
	unsigned last;
	unsigned nr;

	if (!ready)
		return false;

	head = *ring->cq.khead;
	mask = ring->cq.ring_mask;
	if (!(ring->flags & IORING_SETUP_CQE_MIXED)) {
		unsigned shift = io_uring_cqe_shift(ring);

		if (ready < *count)
			*count = ready;
		last = head + *count;
		for (;head != last; head++)
			*(cqes++) = &ring->cq.cqes[(head & mask) << shift];

		return true;
	}

	/*
	 * For mixed CQE rings, CQEs take up one or two slots, and the kernel
	 * may post skip entries to pad out the ring at wrap time. Only return
	 * pointers to real CQEs, with *count denoting the number of CQEs.
	 */
	last = head + ready;
	nr = 0;
	while (head != last && nr < *count) {
		struct io_uring_cqe *cqe = &ring->cq.cqes[head & mask];

		if (cqe->flags & IORING_CQE_F_SKIP) {
			/*
			 * A skip entry can only be consumed if it's at the
			 * current CQ head, stop the batch otherwise. It'll
			 * be at the head for the next peek.
			 */
			if (nr)
				break;
			io_uring_cq_advance(ring, 1);
			head++;
			continue;
		}
		head += io_uring_cqe_nr(cqe);
		cqes[nr++] = cqe;
	}
	*count = nr;
	return nr != 0;
}

/*
 * Fill in an array of IO completions up to count, if any are available.
 * Returns the amount of IO completions filled.
 */
unsigned io_uring_peek_batch_cqe(struct io_uring *ring,
				 struct io_uring_cqe **cqes, unsigned count)
{
	if (io_uring_peek_batch_cqe_(ring, cqes, &count))
		return count;

	if (!cq_ring_needs_flush(ring))
		return 0;

	io_uring_get_events(ring);
	if (!io_uring_peek_batch_cqe_(ring, cqes, &count))
		return 0;

	return count;
}

/*
 * Sync internal state with kernel ring state on the SQ side. Returns the
 * number of pending items in the SQ ring, for the shared ring.
 */
static unsigned __io_uring_flush_sq(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned tail = sq->sqe_tail;

	/*
	 * With IORING_SETUP_SQ_REWIND, the kernel ignores the SQ head / tail
	 * and submits entries from the beginning of the queue. Continue using
	 * the indices as before but reset the tail on submission. With the
	 * head kept to be zero, io_uring_get_sqe() / etc. will work without
	 * any extra changes.
	 */
	if (ring->flags & IORING_SETUP_SQ_REWIND) {
		sq->sqe_tail = 0;
		return tail;
	}

	if (sq->sqe_head != tail) {
		sq->sqe_head = tail;
		/*
		 * Ensure kernel sees the SQE updates before the tail update.
		 */
		if (!(ring->flags & IORING_SETUP_SQPOLL) &&
		    !(ring->int_flags & INT_FLAG_SPARE_PULL))
			*sq->ktail = tail;
		else
			io_uring_smp_store_release(sq->ktail, tail);
	}
	/*
	 * Pull consumers publish head with release; pair it before reusing SQEs.
	 * Other rings retain their existing atomic head load: the kernel only
	 * advances head to indicate that it has finished reading the SQEs.
	 */
	if (ring->int_flags & INT_FLAG_SPARE_PULL)
		return tail - io_uring_smp_load_acquire(sq->khead);
	return tail - IO_URING_READ_ONCE(*sq->khead);
}

/*
 * If we have kernel support for IORING_ENTER_EXT_ARG, then we can use that
 * more efficiently than queueing an internal timeout command.
 */
static int io_uring_wait_cqes_new(struct io_uring *ring,
				  struct io_uring_cqe **cqe_ptr,
				  unsigned wait_nr,
				  struct __kernel_timespec *ts,
				  unsigned int min_wait_usec,
				  sigset_t *sigmask)
{
	struct io_uring_getevents_arg arg = {
		.sigmask	= (unsigned long) sigmask,
		.sigmask_sz	= _NSIG / 8,
		.ts		= (unsigned long) ts
	};
	struct get_data data = {
		.wait_nr	= wait_nr,
		.get_flags	= IORING_ENTER_EXT_ARG,
		.sz		= sizeof(arg),
		.has_ts		= ts != NULL,
		.arg		= &arg
	};

	if (min_wait_usec && ring->features & IORING_FEAT_MIN_TIMEOUT)
		arg.min_wait_usec = min_wait_usec;

	return _io_uring_get_cqe(ring, cqe_ptr, &data);
}

/*
 * Like io_uring_wait_cqe(), except it accepts a timeout value as well. Note
 * that an sqe is used internally to handle the timeout. For kernel doesn't
 * support IORING_FEAT_EXT_ARG, applications using this function must never
 * set sqe->user_data to LIBURING_UDATA_TIMEOUT!
 *
 * For kernels without IORING_FEAT_EXT_ARG (5.10 and older), if 'ts' is
 * specified, the application need not call io_uring_submit() before
 * calling this function, as we will do that on its behalf. From this it also
 * follows that this function isn't safe to use for applications that split SQ
 * and CQ handling between two threads and expect that to work without
 * synchronization, as this function manipulates both the SQ and CQ side.
 *
 * For kernels with IORING_FEAT_EXT_ARG, no implicit submission is done and
 * hence this function is safe to use for applications that split SQ and CQ
 * handling between two threads.
 */
static int __io_uring_submit_timeout(struct io_uring *ring, unsigned wait_nr,
				     struct __kernel_timespec *ts)
{
	struct io_uring_sqe *sqe;
	int ret;

	/*
	 * If the SQ ring is full, we may need to submit IO first
	 */
	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		ret = io_uring_submit(ring);
		if (ret < 0)
			return ret;
		sqe = io_uring_get_sqe(ring);
		if (!sqe)
			return -EAGAIN;
	}
	io_uring_prep_timeout(sqe, ts, wait_nr, 0);
	sqe->user_data = LIBURING_UDATA_TIMEOUT;
	return __io_uring_flush_sq(ring);
}

int io_uring_wait_cqes(struct io_uring *ring, struct io_uring_cqe **cqe_ptr,
		       unsigned wait_nr, struct __kernel_timespec *ts,
		       sigset_t *sigmask)
{
	int to_submit = 0;

	if (ts) {
		if (ring->features & IORING_FEAT_EXT_ARG)
			return io_uring_wait_cqes_new(ring, cqe_ptr, wait_nr,
							ts, 0, sigmask);
		to_submit = __io_uring_submit_timeout(ring, wait_nr, ts);
		if (to_submit < 0)
			return to_submit;
	}

	return __io_uring_get_cqe(ring, cqe_ptr, to_submit, wait_nr, sigmask);
}

int io_uring_wait_cqes_min_timeout(struct io_uring *ring,
				   struct io_uring_cqe **cqe_ptr,
				   unsigned wait_nr,
				   struct __kernel_timespec *ts,
				   unsigned int min_wait_usec, sigset_t *sigmask)
{
	if (!(ring->features & IORING_FEAT_MIN_TIMEOUT))
		return -EINVAL;
	return io_uring_wait_cqes_new(ring, cqe_ptr, wait_nr, ts, min_wait_usec,
					sigmask);
}

int io_uring_submit_and_wait_reg(struct io_uring *ring,
				 struct io_uring_cqe **cqe_ptr,
				 unsigned wait_nr, int reg_index)
{
	unsigned long offset = reg_index * sizeof(struct io_uring_reg_wait);

	if (!(ring->features & IORING_FEAT_EXT_ARG))
		return -EINVAL;

	struct get_data data = {
		.submit		= __io_uring_flush_sq(ring),
		.wait_nr	= wait_nr,
		.get_flags	= IORING_ENTER_EXT_ARG |
				  IORING_ENTER_EXT_ARG_REG,
		.sz		= sizeof(struct io_uring_reg_wait),
		.has_ts		= true,
		.arg		= (void *) (uintptr_t) offset,
	};

	return _io_uring_get_cqe(ring, cqe_ptr, &data);
}

static int __io_uring_submit_and_wait_timeout(struct io_uring *ring,
			struct io_uring_cqe **cqe_ptr, unsigned wait_nr,
			struct __kernel_timespec *ts,
			unsigned int min_wait, sigset_t *sigmask)
{
	int to_submit;

	if (ts) {
		if (ring->features & IORING_FEAT_EXT_ARG) {
			struct io_uring_getevents_arg arg = {
				.sigmask	= (unsigned long) sigmask,
				.sigmask_sz	= _NSIG / 8,
				.min_wait_usec	= min_wait,
				.ts		= (unsigned long) ts
			};
			struct get_data data = {
				.submit		= __io_uring_flush_sq(ring),
				.wait_nr	= wait_nr,
				.get_flags	= IORING_ENTER_EXT_ARG,
				.sz		= sizeof(arg),
				.has_ts		= ts != NULL,
				.arg		= &arg
			};

			return _io_uring_get_cqe(ring, cqe_ptr, &data);
		}
		to_submit = __io_uring_submit_timeout(ring, wait_nr, ts);
		if (to_submit < 0)
			return to_submit;
	} else
		to_submit = __io_uring_flush_sq(ring);

	return __io_uring_get_cqe(ring, cqe_ptr, to_submit, wait_nr, sigmask);
}

int io_uring_submit_and_wait_min_timeout(struct io_uring *ring,
					 struct io_uring_cqe **cqe_ptr,
					 unsigned wait_nr,
					 struct __kernel_timespec *ts,
					 unsigned min_wait,
					 sigset_t *sigmask)
{
	if (!(ring->features & IORING_FEAT_MIN_TIMEOUT))
		return -EINVAL;
	return __io_uring_submit_and_wait_timeout(ring, cqe_ptr, wait_nr, ts,
						  min_wait, sigmask);
}

int io_uring_submit_and_wait_timeout(struct io_uring *ring,
				     struct io_uring_cqe **cqe_ptr,
				     unsigned wait_nr,
				     struct __kernel_timespec *ts,
				     sigset_t *sigmask)
{
	return __io_uring_submit_and_wait_timeout(ring, cqe_ptr, wait_nr, ts, 0,
						  sigmask);
}

/*
 * See io_uring_wait_cqes() - this function is the same, it just always uses
 * '1' as the wait_nr.
 */
int io_uring_wait_cqe_timeout(struct io_uring *ring,
			      struct io_uring_cqe **cqe_ptr,
			      struct __kernel_timespec *ts)
{
	return io_uring_wait_cqes(ring, cqe_ptr, 1, ts, NULL);
}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
static int __io_uring_submit(struct io_uring *ring, unsigned submitted,
			     unsigned wait_nr, bool getevents)
{
	bool cq_needs_enter = getevents || wait_nr || cq_ring_needs_enter(ring);
	unsigned flags = ring_enter_flags(ring);
	int ret;

	liburing_sanitize_ring(ring);

	if (ring->int_flags & INT_FLAG_SPARE_PULL) {
		/* As sq_ring_needs_enter() for a ring we drive: nothing to do. */
		if (!submitted && !cq_needs_enter)
			return 0;
		if (spare_pull_skip(ring, submitted)) {
			if (!cq_needs_enter)
				return submitted;
			ret = __sys_io_uring_enter(ring->enter_ring_fd, 0, wait_nr,
					 flags | IORING_ENTER_GETEVENTS, NULL);
			return ret < 0 ? ret : (int) submitted;
		}
		return __sys_io_uring_enter(ring->enter_ring_fd, submitted,
				wait_nr, flags | (cq_needs_enter ?
				IORING_ENTER_GETEVENTS : 0), NULL);
	}

	if (sq_ring_needs_enter(ring, submitted, &flags) || cq_needs_enter) {
		if (cq_needs_enter)
			flags |= IORING_ENTER_GETEVENTS;

		ret = __sys_io_uring_enter(ring->enter_ring_fd, submitted,
					   wait_nr, flags, NULL);
	} else
		ret = submitted;

	return ret;
}

static int __io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
	return __io_uring_submit(ring, __io_uring_flush_sq(ring), wait_nr, false);
}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
int io_uring_submit(struct io_uring *ring)
{
	return __io_uring_submit_and_wait(ring, 0);
}

/*
 * Like io_uring_submit(), but allows waiting for events as well.
 *
 * Returns number of sqes submitted
 */
int io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
	return __io_uring_submit_and_wait(ring, wait_nr);
}

int io_uring_submit_and_get_events(struct io_uring *ring)
{
	return __io_uring_submit(ring, __io_uring_flush_sq(ring), 0, true);
}

#ifdef LIBURING_INTERNAL
struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring)
{
	return _io_uring_get_sqe(ring);
}
#endif

int __io_uring_sqring_wait(struct io_uring *ring)
{
	int flags = IORING_ENTER_SQ_WAIT | ring_enter_flags(ring);

	return __sys_io_uring_enter(ring->enter_ring_fd, 0, 0, flags, NULL);
}
