/*
 *  linux/kernel/time.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  This file contains the interface functions for the various
 *  time related system calls: time, stime, gettimeofday, settimeofday,
 *			       adjtime
 */
/*
 * Modification history kernel/time.c
 *
 * 1993-09-02    Philip Gladstone
 *      Created file with time related functions from sched/core.c and adjtimex()
 * 1993-10-08    Torsten Duwe
 *      adjtime interface update and CMOS clock write code
 * 1995-08-13    Torsten Duwe
 *      kernel PLL updated to 1994-12-13 specs (rfc-1589)
 * 1999-01-16    Ulrich Windl
 *	Introduced error checking for many cases in adjtimex().
 *	Updated NTP code according to technical memorandum Jan '96
 *	"A Kernel Model for Precision Timekeeping" by Dave Mills
 *	Allow time_constant larger than MAXTC(6) for NTP v4 (MAXTC == 10)
 *	(Even though the technical memorandum forbids it)
 * 2004-07-14	 Christoph Lameter
 *	Added getnstimeofday to allow the posix timer functions to return
 *	with nanosecond accuracy
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/timex.h>
#include <linux/capability.h>
#include <linux/timekeeper_internal.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/math64.h>
#include <linux/ptrace.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <generated/timeconst.h>
#include "timekeeping.h"

/*
 * The timezone where the local system is located.  Used as a default by some
 * programs who obtain this value by using gettimeofday.
 */
struct timezone sys_tz;

EXPORT_SYMBOL(sys_tz);

#ifdef __ARCH_WANT_SYS_TIME

/*
 * sys_time() can be implemented in user-level using
 * sys_gettimeofday().  Is this for backwards compatibility?  If so,
 * why not move it into the appropriate arch directory (for those
 * architectures that need it).
 */
SYSCALL_DEFINE1(time, time_t __user *, tloc)
{
	time_t i = get_seconds();

	if (tloc) {
		if (put_user(i,tloc))
			return -EFAULT;
	}
	force_successful_syscall_return();
	return i;
}

/*
 * sys_stime() can be implemented in user-level using
 * sys_settimeofday().  Is this for backwards compatibility?  If so,
 * why not move it into the appropriate arch directory (for those
 * architectures that need it).
 */

SYSCALL_DEFINE1(stime, time_t __user *, tptr)
{
	struct timespec tv;
	int err;

	if (get_user(tv.tv_sec, tptr))
		return -EFAULT;

	tv.tv_nsec = 0;

	err = security_settime(&tv, NULL);
	if (err)
		return err;

	do_settimeofday(&tv);
	return 0;
}

#endif /* __ARCH_WANT_SYS_TIME */

SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv,
		struct timezone __user *, tz)
{
	if (likely(tv != NULL)) {
		struct timeval ktv;
		do_gettimeofday(&ktv);
		if (copy_to_user(tv, &ktv, sizeof(ktv)))
			return -EFAULT;
	}
	if (unlikely(tz != NULL)) {
		if (copy_to_user(tz, &sys_tz, sizeof(sys_tz)))
			return -EFAULT;
	}
	return 0;
}

/*
 * Indicates if there is an offset between the system clock and the hardware
 * clock/persistent clock/rtc.
 */
int persistent_clock_is_local;

/*
 * Adjust the time obtained from the CMOS to be UTC time instead of
 * local time.
 *
 * This is ugly, but preferable to the alternatives.  Otherwise we
 * would either need to write a program to do it in /etc/rc (and risk
 * confusion if the program gets run more than once; it would also be
 * hard to make the program warp the clock precisely n hours)  or
 * compile in the timezone information into the kernel.  Bad, bad....
 *
 *						- TYT, 1992-01-01
 *
 * The best thing to do is to keep the CMOS clock in universal time (UTC)
 * as real UNIX machines always do it. This avoids all headaches about
 * daylight saving times and warping kernel clocks.
 */
static inline void warp_clock(void)
{
	if (sys_tz.tz_minuteswest != 0) {
		struct timespec adjust;

		persistent_clock_is_local = 1;
		adjust.tv_sec = sys_tz.tz_minuteswest * 60;
		adjust.tv_nsec = 0;
		timekeeping_inject_offset(&adjust);
	}
}

/* ASUS_BSP +++ jeff_gu Add Event log when set time */
#include <linux/rtc.h>

struct asus_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

#define ASUS_LEAPS_THRU_END_OF(y) ((y)/4 - (y)/100 + (y)/400)

static const unsigned char asus_days_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

/*
 * The number of days in the month.
 */
static int asus_month_days(unsigned int month, unsigned int year)
{
	return asus_days_in_month[month] + (is_leap_year(year) && month == 1);
}

/*
 * Convert seconds since 01-01-1970 00:00:00 to Gregorian date.
 */
static void asus_time_to_tm(unsigned long time, struct asus_time *tm)
{
	unsigned int month, year;
	int days;

	days = time / 86400;
	time -= (unsigned int) days * 86400;

	/* day of the week, 1970-01-01 was a Thursday */
	tm->tm_wday = (days + 4) % 7;

	year = 1970 + days / 365;
	days -= (year - 1970) * 365
		+ ASUS_LEAPS_THRU_END_OF(year - 1)
		- ASUS_LEAPS_THRU_END_OF(1970 - 1);
	if (days < 0) {
		year -= 1;
		days += 365 + is_leap_year(year);
	}
	tm->tm_year = year - 1900;
	tm->tm_yday = days + 1;

	for (month = 0; month < 11; month++) {
		int newdays;

		newdays = days - asus_month_days(month, year);
		if (newdays < 0)
			break;
		days = newdays;
	}
	tm->tm_mon = month;
	tm->tm_mday = days + 1;

	tm->tm_hour = time / 3600;
	time -= tm->tm_hour * 3600;
	tm->tm_min = time / 60;
	tm->tm_sec = time - tm->tm_min * 60;

	tm->tm_isdst = 0;
}

/* ASUS_BSP --- jeff_gu Add Event log when set time  */

/*
 * In case for some reason the CMOS clock has not already been running
 * in UTC, but in some local time: The first time we set the timezone,
 * we will warp the clock so that it is ticking UTC time instead of
 * local time. Presumably, if someone is setting the timezone then we
 * are running in an environment where the programs understand about
 * timezones. This should be done at boot time in the /etc/rc script,
 * as soon as possible, so that the clock can be set right. Otherwise,
 * various programs will get confused when the clock gets warped.
 */

int do_sys_settimeofday64(const struct timespec64 *tv, const struct timezone *tz)
{
	/* ASUS_BSP +++ jeff_gu Add Event log when set time */
	struct timespec tmp_time;
	struct asus_time ori_tm, new_tm;
	static struct asus_time last_tm;
	/* ASUS_BSP --- jeff_gu Add Event log when set time  */

	static int firsttime = 1;
	int error = 0;

	/* ASUS_BSP +++ jeff_gu Add Event log when set time */
	getnstimeofday(&tmp_time);
	tmp_time.tv_sec -= sys_tz.tz_minuteswest * 60;
	asus_time_to_tm(tmp_time.tv_sec, &ori_tm);
	/* ASUS_BSP --- jeff_gu Add Event log when set time */

	if (tv && !timespec64_valid(tv))
		return -EINVAL;

	error = security_settime64(tv, tz);
	if (error)
		return error;

	if (tz) {
		/* Verify we're witin the +-15 hrs range */
		if (tz->tz_minuteswest > 15*60 || tz->tz_minuteswest < -15*60)
			return -EINVAL;

		sys_tz = *tz;
		update_vsyscall_tz();
		if (firsttime) {
			firsttime = 0;
			if (!tv)
				warp_clock();
		}
	}
	/* ASUS_BSP +++ jeff_gu Add Event log when set time zone */
	if (tv != NULL){
		set_normalized_timespec(&tmp_time,tv->tv_sec,tv->tv_nsec);
	} else {
		getnstimeofday(&tmp_time);
	}
	tmp_time.tv_sec -= sys_tz.tz_minuteswest * 60;
	asus_time_to_tm(tmp_time.tv_sec, &new_tm);
	printk("[UTS] RTC update: Current Datetime: %04d-%02d-%02d %02d:%02d:%02d,Update Datetime: %04d-%02d-%02d %02d:%02d:%02d\r\n",
		ori_tm.tm_year + 1900,
		ori_tm.tm_mon + 1,
		ori_tm.tm_mday,
		ori_tm.tm_hour,
		ori_tm.tm_min,
		ori_tm.tm_sec,
		new_tm.tm_year + 1900,
		new_tm.tm_mon + 1,
		new_tm.tm_mday,
		new_tm.tm_hour,
		new_tm.tm_min,
		new_tm.tm_sec);
	if(memcmp(&last_tm, &new_tm, sizeof(new_tm))){
		ASUSEvtlog("[UTS] RTC update: Current Datetime: %04d-%02d-%02d %02d:%02d:%02d,Update Datetime: %04d-%02d-%02d %02d:%02d:%02d\r\n",
			ori_tm.tm_year + 1900,
			ori_tm.tm_mon + 1,
			ori_tm.tm_mday,
			ori_tm.tm_hour,
			ori_tm.tm_min,
			ori_tm.tm_sec,
			new_tm.tm_year + 1900,
			new_tm.tm_mon + 1,
			new_tm.tm_mday,
			new_tm.tm_hour,
			new_tm.tm_min,
			new_tm.tm_sec);
		memcpy(&last_tm, &new_tm, sizeof(new_tm));
	}
	/* ASUS_BSP --- jeff_gu Add Event log when set time zone */
	if (tv)
		return do_settimeofday64(tv);
	return 0;
}

SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv,
		struct timezone __user *, tz)
{
	struct timeval user_tv;
	struct timespec	new_ts = {0};
	struct timezone new_tz;

	if (tv) {
		if (copy_from_user(&user_tv, tv, sizeof(*tv)))
			return -EFAULT;

		if (!timeval_valid(&user_tv))
			return -EINVAL;

		new_ts.tv_sec = user_tv.tv_sec;
		new_ts.tv_nsec = user_tv.tv_usec * NSEC_PER_USEC;
	}
	if (tz) {
		if (copy_from_user(&new_tz, tz, sizeof(*tz)))
			return -EFAULT;
	}

	return do_sys_settimeofday(tv ? &new_ts : NULL, tz ? &new_tz : NULL);
}

SYSCALL_DEFINE1(adjtimex, struct timex __user *, txc_p)
{
	struct timex txc;		/* Local copy of parameter */
	int ret;

	/* Copy the user data space into the kernel copy
	 * structure. But bear in mind that the structures
	 * may change
	 */
	if(copy_from_user(&txc, txc_p, sizeof(struct timex)))
		return -EFAULT;
	ret = do_adjtimex(&txc);
	return copy_to_user(txc_p, &txc, sizeof(struct timex)) ? -EFAULT : ret;
}

/*
 * Add two timespec64 values and do a safety check for overflow.
 * It's assumed that both values are valid (>= 0).
 * And, each timespec64 is in normalized form.
 */
struct timespec64 timespec64_add_safe(const struct timespec64 lhs,
				const struct timespec64 rhs)
{
	struct timespec64 res;

	set_normalized_timespec64(&res, (timeu64_t) lhs.tv_sec + rhs.tv_sec,
			lhs.tv_nsec + rhs.tv_nsec);

	if (unlikely(res.tv_sec < lhs.tv_sec || res.tv_sec < rhs.tv_sec)) {
		res.tv_sec = TIME64_MAX;
		res.tv_nsec = 0;
	}

	return res;
}
