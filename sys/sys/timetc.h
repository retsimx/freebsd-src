/*-
 * SPDX-License-Identifier: Beerware
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.ORG> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

#ifndef _SYS_TIMETC_H_
#define	_SYS_TIMETC_H_

#ifndef _KERNEL
#error "no user-serviceable parts inside"
#endif

/*-
 * `struct timecounter' is the interface between the hardware which implements
 * a timecounter and the MI code which uses this to keep track of time.
 *
 * A timecounter is a binary counter which has two properties:
 *    * it runs at a fixed, known frequency.
 *    * it has sufficient bits to not roll over in less than approximately
 *      max(2 msec, 2/HZ seconds).  (The value 2 here is really 1 + delta,
 *      for some indeterminate value of delta.)
 */

struct timecounter;
struct vdso_timehands;
struct vdso_timehands32;
typedef u_int timecounter_get_t(struct timecounter *);
typedef void timecounter_pps_t(struct timecounter *);
typedef uint32_t timecounter_fill_vdso_timehands_t(struct vdso_timehands *,
    struct timecounter *);
typedef uint32_t timecounter_fill_vdso_timehands32_t(struct vdso_timehands32 *,
    struct timecounter *);

struct timecounter {
	timecounter_get_t	*tc_get_timecount;
		/*
		 * This function reads the counter.  It is not required to
		 * mask any unimplemented bits out, as long as they are
		 * constant.
		 */
	timecounter_pps_t	*tc_poll_pps;
		/*
		 * This function is optional.  It will be called whenever the
		 * timecounter is rewound, and is intended to check for PPS
		 * events.  Normal hardware does not need it but timecounters
		 * which latch PPS in hardware do.
		 */
	u_int 			tc_counter_mask;
		/* This mask should mask off any unimplemented bits. */
	uint64_t		tc_frequency;
		/* Frequency of the counter in Hz. */
	const char		*tc_name;
		/* Name of the timecounter. */
	int			tc_quality;
		/*
		 * Used to determine if this timecounter is better than
		 * another timecounter higher means better.  Negative
		 * means "only use at explicit request".
		 */
	u_int			tc_flags;
#define	TC_FLAGS_C2STOP		1	/* Timer dies in C2+. */
#define	TC_FLAGS_SUSPEND_SAFE	2	/*
					 * Timer functional across
					 * suspend/resume.
					 */

	void			*tc_priv;
		/* Pointer to the timecounter's private parts. */
	struct timecounter	*tc_next;
		/* Pointer to the next timecounter. */
	timecounter_fill_vdso_timehands_t *tc_fill_vdso_timehands;
	timecounter_fill_vdso_timehands32_t *tc_fill_vdso_timehands32;
};

extern struct timecounter *timecounter;
extern int tc_min_ticktock_freq; /*
				  * Minimal tc_ticktock() call frequency,
				  * required to handle counter wraps.
				  */

u_int64_t tc_getfrequency(void);
void	tc_init(struct timecounter *tc);
void	tc_setclock(struct timespec *ts);
void	tc_ticktock(long cnt);
void	cpu_tick_calibration(void);

/*
 * K24-T00: hibernate_machdep_prepare() (sys/amd64/amd64/hibernate_machdep.c)
 * must self-copy the page-table path backing the timehands ring buffer
 * (the `ths[]` array in kern_tc.c) before the K-10 destructive copy runs,
 * the same protection already applied to pc_gdt/vm_page_array/kstack.
 * `timehands`/`ths` are file-static in kern_tc.c, so this accessor exposes
 * only the byte range needed for that walk, not the pointers themselves.
 */
void	tc_hibernate_selfcopy_range(uintptr_t *va_out, size_t *len_out);

#ifdef SYSCTL_DECL
SYSCTL_DECL(_kern_timecounter);
#endif

/**
 * clockcalib(clk, clkname):
 * Return the frequency of the provided timer, as calibrated against the
 * current best-available timecounter.
 */
uint64_t clockcalib(uint64_t (*)(void), const char *);

#endif /* !_SYS_TIMETC_H_ */
