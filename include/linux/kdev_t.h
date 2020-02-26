/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KDEV_T_H
#define _LINUX_KDEV_T_H

#include <uapi/linux/kdev_t.h>
#include <uapi/linux/major.h>
#include <uapi/linux/mem_minor.h>
#include <uapi/linux/stat.h>

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})

/* acceptable for old filesystems */
static inline bool old_valid_dev(dev_t dev)
{
	return MAJOR(dev) < 256 && MINOR(dev) < 256;
}

static inline u16 old_encode_dev(dev_t dev)
{
	return (MAJOR(dev) << 8) | MINOR(dev);
}

static inline dev_t old_decode_dev(u16 val)
{
	return MKDEV((val >> 8) & 255, val & 255);
}

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline dev_t new_decode_dev(u32 dev)
{
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return MKDEV(major, minor);
}

static inline u64 huge_encode_dev(dev_t dev)
{
	return new_encode_dev(dev);
}

static inline dev_t huge_decode_dev(u64 dev)
{
	return new_decode_dev(dev);
}

static inline int sysv_valid_dev(dev_t dev)
{
	return MAJOR(dev) < (1<<14) && MINOR(dev) < (1<<18);
}

static inline u32 sysv_encode_dev(dev_t dev)
{
	return MINOR(dev) | (MAJOR(dev) << 18);
}

static inline unsigned sysv_major(u32 dev)
{
	return (dev >> 18) & 0x3fff;
}

static inline unsigned sysv_minor(u32 dev)
{
	return dev & 0x3ffff;
}

#ifdef CONFIG_WHITELIST_MKNOD_CHAR_DEVICES
/*
 * Whitelist some basic devices. These devices have all of these particularly
 * safe characteristics:
 * 1) Limited on-disk size (Most regular files will take more space)
 * 2) Limited in-memory effective size
 * 3) Pseudo devices/RAM access only
 * 4) Volatile (userspace doesn't expect device contents to persist)
 * 5) Insanely-low CPU usage for reads/writes
 * 6) Never shared; Private
 */
static inline bool is_whitelisted_mknod_char_dev(mode_t mode, dev_t dev)
{
	if (!S_ISCHR(mode) || MAJOR(dev) != MEM_MAJOR)
		return false;
	switch(MINOR(dev)) {
	case DEV_NULL_MINOR:
	case DEV_ZERO_MINOR:
	case DEV_FULL_MINOR:
		return true;
	default:
		return false;
	}
}
#else
static inline bool is_whitelisted_mknod_char_dev(mode_t mode, dev_t dev)
{
	return false;
}
#endif /* CONFIG_WHITELIST_MKNOD_CHAR_DEVICES */

#endif
