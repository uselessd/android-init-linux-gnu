/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <time.h>
#include <sys/swap.h>
#include <dirent.h>

#include "logwrap.h"
#include "util.h"
#include "strlcat.h"

#include "fs_mgr_priv.h"

#define ZRAM_CONF_DEV "/sys/block/zram0/disksize"
#define MKSWAP_BIN "/sbin/mkswap"
#define E2FSCK_BIN "/sbin/e2fsck"
#define FSCK_LOG_FILE "/var/log/android-e2fsck"

static void check_fs(char *blk_device, char *fs_type, char *target)
{
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char tmpmnt_opts[64] = "errors=remount-ro";
    char *e2fsck_argv[] = {
        E2FSCK_BIN,
        "-y",
        blk_device
    };

    /* Check for the types of filesystems we know how to check */
    if (!strcmp(fs_type, "ext2") || !strcmp(fs_type, "ext3") || !strcmp(fs_type, "ext4")) {
        /*
         * First try to mount and unmount the filesystem.  We do this because
         * the kernel is more efficient than e2fsck in running the journal and
         * processing orphaned inodes, and on at least one device with a
         * performance issue in the emmc firmware, it can take e2fsck 2.5 minutes
         * to do what the kernel does in about a second.
         *
         * After mounting and unmounting the filesystem, run e2fsck, and if an
         * error is recorded in the filesystem superblock, e2fsck will do a full
         * check.  Otherwise, it does nothing.  If the kernel cannot mount the
         * filesytsem due to an error, e2fsck is still run to do a full check
         * fix the filesystem.
         */
        errno = 0;
        if (!strcmp(fs_type, "ext4")) {
            // This option is only valid with ext4
            strlcat(tmpmnt_opts, ",nomblk_io_submit", sizeof(tmpmnt_opts));
        }
        ret = mount(blk_device, target, fs_type, tmpmnt_flags, tmpmnt_opts);
        INFO("%s(): mount(%s,%s,%s)=%d: %s\n",
             __func__, blk_device, target, fs_type, ret, strerror(errno));
        if (!ret) {
            int i;
            for (i = 0; i < 5; i++) {
                // Try to umount 5 times before continuing on.
                // Should we try rebooting if all attempts fail?
                int result = umount(target);
                if (result == 0) {
                    INFO("%s(): unmount(%s) succeeded\n", __func__, target);
                    break;
                }
                ERROR("%s(): umount(%s)=%d: %s\n", __func__, target, result, strerror(errno));
                sleep(1);
            }
        }

        /*
         * Some system images do not have e2fsck for licensing reasons
         * (e.g. recent SDK system images). Detect these and skip the check.
         */
        if (access(E2FSCK_BIN, X_OK)) {
            INFO("Not running %s on %s (executable not in system image)\n",
                 E2FSCK_BIN, blk_device);
        } else {
            INFO("Running %s on %s\n", E2FSCK_BIN, blk_device);

            ret = android_fork_execvp_ext(ARRAY_SIZE(e2fsck_argv), e2fsck_argv,
                                        &status, true, LOG_KLOG | LOG_FILE,
                                        true, FSCK_LOG_FILE);

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                ERROR("Failed trying to run %s\n", E2FSCK_BIN);
            }
        }
     }

    return;
}

static int mount_with_alternatives(struct fstab *fstab, int start_idx, int *end_idx, int *attempted_idx)
{
    int i;
    int mount_errno = 0;
    int mounted = 0;

    if (!end_idx || !attempted_idx || start_idx >= fstab->num_entries) {
      errno = EINVAL;
      if (end_idx) *end_idx = start_idx;
      if (attempted_idx) *end_idx = start_idx;
      return -1;
    }

    /* Hunt down an fstab entry for the same mount point that might succeed */
    for (i = start_idx;
         /* We required that fstab entries for the same mountpoint be consecutive */
         i < fstab->num_entries && !strcmp(fstab->recs[start_idx].mount_point, fstab->recs[i].mount_point);
         i++) {
            /*
             * Don't try to mount/encrypt the same mount point again.
             * Deal with alternate entries for the same point which are required to be all following
             * each other.
             */
            if (mounted) {
                ERROR("%s(): skipping fstab dup mountpoint=%s rec[%d].fs_type=%s already mounted as %s.\n", __func__,
                     fstab->recs[i].mount_point, i, fstab->recs[i].fs_type, fstab->recs[*attempted_idx].fs_type);
                continue;
            }

            if (fstab->recs[i].fs_mgr_flags & MF_CHECK) {
                check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                         fstab->recs[i].mount_point);
            }
            if (!mount(fstab->recs[i].blk_device, fstab->recs[i].mount_point, fstab->recs[i].fs_type,
                       fstab->recs[i].flags, fstab->recs[i].fs_options)) {
                *attempted_idx = i;
                mounted = 1;
                if (i != start_idx) {
                    ERROR("%s(): Mounted %s on %s with fs_type=%s instead of %s\n", __func__,
                         fstab->recs[i].blk_device, fstab->recs[i].mount_point, fstab->recs[i].fs_type,
                         fstab->recs[start_idx].fs_type);
                }
            } else {
                /* back up errno for crypto decisions */
                mount_errno = errno;
            }
    }

    /* Adjust i for the case where it was still withing the recs[] */
    if (i < fstab->num_entries) --i;

    *end_idx = i;
    if (!mounted) {
        *attempted_idx = start_idx;
        errno = mount_errno;
        return -1;
    }
    return 0;
}

/* When multiple fstab records share the same mount_point, it will
 * try to mount each one in turn, and ignore any duplicates after a
 * first successful mount.
 * Returns -1 on error, and  FS_MGR_MNTALL_* otherwise.
 */
int fs_mgr_mount_all(struct fstab *fstab)
{
    int i = 0;
    int encryptable = FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
    int error_count = 0;
    int mret = -1;
    int mount_errno = 0;
    int attempted_idx = -1;

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't mount entries that are managed by vold */
        if (fstab->recs[i].fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) {
            continue;
        }

        /* Skip swap and raw partition entries such as boot, recovery, etc */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            continue;
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        int last_idx_inspected;
        mret = mount_with_alternatives(fstab, i, &last_idx_inspected, &attempted_idx);
        i = last_idx_inspected;
        mount_errno = errno;

        /* mount(2) returned an error */
        if (mret && mount_errno != EBUSY && mount_errno != EACCES) {
            ERROR("Failed to mount an un-encryptable or wiped partition on"
                   "%s at %s options: %s error: %s\n",
                   fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                   fstab->recs[attempted_idx].fs_options, strerror(mount_errno));
            ++error_count;
            continue;
        }
    }

    if (error_count) {
        return -1;
    } else {
        return encryptable;
    }
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs",
                MS_NOATIME | MS_NOSUID | MS_NODEV, CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        ERROR("Cannot mount tmpfs filesystem at %s\n", n_name);
        return -1;
    }

    /* Success */
    return 0;
}

int fs_mgr_unmount_all(struct fstab *fstab)
{
    int i = 0;
    int ret = 0;

    if (!fstab) {
        return -1;
    }

    while (fstab->recs[i].blk_device) {
        if (umount(fstab->recs[i].mount_point)) {
            ERROR("Cannot unmount filesystem at %s\n", fstab->recs[i].mount_point);
            ret = -1;
        }
        i++;
    }

    return ret;
}

/* This must be called after mount_all, because the mkswap command needs to be
 * available.
 */
int fs_mgr_swapon_all(struct fstab *fstab)
{
    int i = 0;
    int flags = 0;
    int err = 0;
    int ret = 0;
    int status;
    char *mkswap_argv[2] = {
        MKSWAP_BIN,
        NULL
    };

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Skip non-swap entries */
        if (strcmp(fstab->recs[i].fs_type, "swap")) {
            continue;
        }

        if (fstab->recs[i].zram_size > 0) {
            /* A zram_size was specified, so we need to configure the
             * device.  There is no point in having multiple zram devices
             * on a system (all the memory comes from the same pool) so
             * we can assume the device number is 0.
             */
            FILE *zram_fp;

            zram_fp = fopen(ZRAM_CONF_DEV, "r+");
            if (zram_fp == NULL) {
                ERROR("Unable to open zram conf device %s\n", ZRAM_CONF_DEV);
                ret = -1;
                continue;
            }
            fprintf(zram_fp, "%d\n", fstab->recs[i].zram_size);
            fclose(zram_fp);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        /* Initialize the swap area */
        mkswap_argv[1] = fstab->recs[i].blk_device;
        err = android_fork_execvp_ext(ARRAY_SIZE(mkswap_argv), mkswap_argv,
                                      &status, true, LOG_KLOG, false, NULL);
        if (err) {
            ERROR("mkswap failed for %s\n", fstab->recs[i].blk_device);
            ret = -1;
            continue;
        }

        /* If -1, then no priority was specified in fstab, so don't set
         * SWAP_FLAG_PREFER or encode the priority */
        if (fstab->recs[i].swap_prio >= 0) {
            flags = (fstab->recs[i].swap_prio << SWAP_FLAG_PRIO_SHIFT) &
                    SWAP_FLAG_PRIO_MASK;
            flags |= SWAP_FLAG_PREFER;
        } else {
            flags = 0;
        }
        err = swapon(fstab->recs[i].blk_device, flags);
        if (err) {
            ERROR("swapon failed for %s\n", fstab->recs[i].blk_device);
            ret = -1;
        }
    }

    return ret;
}
