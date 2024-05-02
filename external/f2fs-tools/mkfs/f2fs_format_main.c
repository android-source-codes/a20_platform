/**
 * f2fs_format.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef ANDROID_WINDOWS_HOST
#include <sys/mount.h>
#endif
#include <time.h>
#include <uuid/uuid.h>
#include <errno.h>

#include "config.h"
#ifdef HAVE_LIBBLKID
#  include <blkid/blkid.h>
#endif

#include "f2fs_fs.h"
#include "f2fs_format_utils.h"

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
extern struct sparse_file *f2fs_sparse_file;
#endif

extern struct f2fs_configuration c;
static int force_overwrite = 0;

INIT_FEATURE_TABLE;

static void mkfs_usage()
{
	MSG(0, "\nUsage: mkfs.f2fs [options] device [sectors]\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -a heap-based allocation [default:0]\n");
	MSG(0, "  -c device1[,device2,...] up to 7 additional devices, except meta device\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -e [cold file ext list] e.g. \"mp3,gif,mov\"\n");
	MSG(0, "  -E [hot file ext list] e.g. \"db\"\n");
	MSG(0, "  -f force overwrite of the existing filesystem\n");
	MSG(0, "  -g add default options\n");
	MSG(0, "  -i extended node bitmap, node ratio is 20%% by default\n");
	MSG(0, "  -l label\n");
	MSG(0, "  -m support zoned block device [default:0]\n");
	MSG(0, "  -o overprovision percentage [default:auto]\n");
	MSG(0, "  -O feature1[,feature2,...] e.g. \"encrypt\"\n");
	MSG(0, "  -C [encoding[:flag1,...]] Support casefolding with optional flags\n");
	MSG(0, "  -q quiet mode\n");
	MSG(0, "  -R root_owner [default: 0:0]\n");
	MSG(0, "  -s # of segments per section [default:1]\n");
	MSG(0, "  -S sparse mode\n");
	MSG(0, "  -t 0: nodiscard, 1: discard [default:1]\n");
	MSG(0, "  -w wanted sector size\n");
	MSG(0, "  -z # of sections per zone [default:1]\n");
	MSG(0, "  -r maximum # of expandable sectors [default:0]\n");
	MSG(0, "  -V print the version number and exit\n");
	MSG(0, "sectors: number of sectors [default: determined by device size]\n");
	exit(1);
}

static void f2fs_show_info()
{
	MSG(0, "\n\tF2FS-tools: mkfs.f2fs Ver: %s (%s)\n\n",
				F2FS_TOOLS_VERSION,
				F2FS_TOOLS_DATE);
	if (c.heap == 0)
		MSG(0, "Info: Disable heap-based policy\n");

	MSG(0, "Info: Debug level = %d\n", c.dbg_lv);
	if (c.extension_list[0])
		MSG(0, "Info: Add new cold file extension list\n");
	if (c.extension_list[1])
		MSG(0, "Info: Add new hot file extension list\n");

	if (strlen(c.vol_label))
		MSG(0, "Info: Label = %s\n", c.vol_label);
	MSG(0, "Info: Trim is %s\n", c.trim ? "enabled": "disabled");

	if (c.defset == CONF_ANDROID)
		MSG(0, "Info: Set conf for android\n");
}

static void add_default_options(void)
{
	switch (c.defset) {
	case CONF_ANDROID:
		/* -d1 -f -O encrypt -O quota -O verity -w 4096 -R 0:0 */
		c.dbg_lv = 1;
		force_overwrite = 1;
		c.feature |= cpu_to_le32(F2FS_FEATURE_ENCRYPT);
		c.feature |= cpu_to_le32(F2FS_FEATURE_QUOTA_INO);
		c.feature |= cpu_to_le32(F2FS_FEATURE_VERITY);
		c.wanted_sector_size = 4096;
		c.root_uid = c.root_gid = 0;
		break;
	}
}

static void f2fs_parse_options(int argc, char *argv[])
{
	static const char *option_string = "qa:c:C:d:e:E:g:il:mo:O:R:s:S:z:t:Vfw:r:";
	int32_t option=0;
	int val;
	char *token;

	while ((option = getopt(argc,argv,option_string)) != EOF) {
		int ret = 0;

		switch (option) {
		case 'q':
			c.dbg_lv = -1;
			break;
		case 'a':
			c.heap = atoi(optarg);
			break;
		case 'c':
			if (c.ndevs >= MAX_DEVICES) {
				MSG(0, "Error: Too many devices\n");
				mkfs_usage();
			}

			if (strlen(optarg) > MAX_PATH_LEN) {
				MSG(0, "Error: device path should be less than "
					"%d characters\n", MAX_PATH_LEN);
				mkfs_usage();
			}
			c.devices[c.ndevs++].path = strdup(optarg);
			break;
		case 'd':
			c.dbg_lv = atoi(optarg);
			break;
		case 'e':
			c.extension_list[0] = strdup(optarg);
			break;
		case 'E':
			c.extension_list[1] = strdup(optarg);
			break;
		case 'g':
			if (!strcmp(optarg, "android"))
				c.defset = CONF_ANDROID;
			break;
		case 'i':
			c.large_nat_bitmap = 1;
			break;
		case 'l':		/*v: volume label */
			if (strlen(optarg) > 512) {
				MSG(0, "Error: Volume Label should be less than "
						"512 characters\n");
				mkfs_usage();
			}
			c.vol_label = optarg;
			break;
		case 'm':
			c.zoned_mode = 1;
			break;
		case 'o':
			c.overprovision = atof(optarg);
			break;
		case 'O':
			if (parse_feature(feature_table, optarg))
				mkfs_usage();
			break;
		case 'R':
			if (parse_root_owner(optarg, &c.root_uid, &c.root_gid))
				mkfs_usage();
			break;
		case 's':
			c.segs_per_sec = atoi(optarg);
			break;
		case 'S':
			c.device_size = atoll(optarg);
			c.device_size &= (~((u_int64_t)(F2FS_BLKSIZE - 1)));
			c.sparse_mode = 1;
			break;
		case 'z':
			c.secs_per_zone = atoi(optarg);
			break;
		case 't':
			c.trim = atoi(optarg);
			break;
		case 'f':
			force_overwrite = 1;
			break;
		case 'w':
			c.wanted_sector_size = atoi(optarg);
			break;
		case 'r':
			if (strncmp(optarg, "0x", 2))
				ret = sscanf(optarg, "%"PRIu64"",
						&c.target_sectors);
			else
				ret = sscanf(optarg, "%"PRIx64"",
						&c.target_sectors);
			ASSERT(ret >= 0);
			break;
		case 'V':
			show_version("mkfs.f2fs");
			exit(0);
		case 'C':
			token = strtok(optarg, ":");
			val = f2fs_str2encoding(token);
			if (val < 0) {
				MSG(0, "\tError: Unknown encoding %s\n", token);
				mkfs_usage();
			}
			c.s_encoding = val;
			token = strtok(NULL, "");
			val = f2fs_str2encoding_flags(&token, &c.s_encoding_flags);
			if (val) {
				MSG(0, "\tError: Unknown flag %s\n",token);
				mkfs_usage();
			}
			c.feature |= cpu_to_le32(F2FS_FEATURE_CASEFOLD);
			break;
		default:
			MSG(0, "\tError: Unknown option %c\n",option);
			mkfs_usage();
			break;
		}
	}

	add_default_options();

	if (!(c.feature & cpu_to_le32(F2FS_FEATURE_EXTRA_ATTR))) {
		if (c.feature & cpu_to_le32(F2FS_FEATURE_PRJQUOTA)) {
			MSG(0, "\tInfo: project quota feature should always be "
				"enabled with extra attr feature\n");
			exit(1);
		}
		if (c.feature & cpu_to_le32(F2FS_FEATURE_INODE_CHKSUM)) {
			MSG(0, "\tInfo: inode checksum feature should always be "
				"enabled with extra attr feature\n");
			exit(1);
		}
		if (c.feature & cpu_to_le32(F2FS_FEATURE_FLEXIBLE_INLINE_XATTR)) {
			MSG(0, "\tInfo: flexible inline xattr feature should always be "
				"enabled with extra attr feature\n");
			exit(1);
		}
		if (c.feature & cpu_to_le32(F2FS_FEATURE_INODE_CRTIME)) {
			MSG(0, "\tInfo: inode crtime feature should always be "
				"enabled with extra attr feature\n");
			exit(1);
		}
		if (c.feature & cpu_to_le32(F2FS_FEATURE_COMPRESSION)) {
			MSG(0, "\tInfo: compression feature should always be "
				"enabled with extra attr feature\n");
			exit(1);
		}
	}

	if (optind >= argc) {
		MSG(0, "\tError: Device not specified\n");
		mkfs_usage();
	}

	/* [0] : META, [1 to MAX_DEVICES - 1] : NODE/DATA */
	c.devices[0].path = strdup(argv[optind]);

	if ((optind + 1) < argc) {
		if (c.ndevs > 1) {
			MSG(0, "\tError: Not support custom size on multi-devs.\n");
			mkfs_usage();
		}
		c.wanted_total_sectors = atoll(argv[optind+1]);
	}

	if (c.sparse_mode)
		c.trim = 0;

	if (c.zoned_mode)
		c.feature |= cpu_to_le32(F2FS_FEATURE_BLKZONED);
}

#ifdef HAVE_LIBBLKID
static int f2fs_dev_is_overwrite(const char *device)
{
	const char	*type;
	blkid_probe	pr = NULL;
	int		ret = -1;

	if (!device || !*device)
		return 0;

	pr = blkid_new_probe_from_filename(device);
	if (!pr)
		goto out;

	ret = blkid_probe_enable_partitions(pr, 1);
	if (ret < 0)
		goto out;

	ret = blkid_do_fullprobe(pr);
	if (ret < 0)
		goto out;

	/*
	 * Blkid returns 1 for nothing found and 0 when it finds a signature,
	 * but we want the exact opposite, so reverse the return value here.
	 *
	 * In addition print some useful diagnostics about what actually is
	 * on the device.
	 */
	if (ret) {
		ret = 0;
		goto out;
	}

	if (!blkid_probe_lookup_value(pr, "TYPE", &type, NULL)) {
		MSG(0, "\t%s appears to contain an existing filesystem (%s).\n",
			device, type);
	} else if (!blkid_probe_lookup_value(pr, "PTTYPE", &type, NULL)) {
		MSG(0, "\t%s appears to contain a partition table (%s).\n",
			device, type);
	} else {
		MSG(0, "\t%s appears to contain something weird according to blkid\n",
			device);
	}
	ret = 1;
out:
	if (pr)
		blkid_free_probe(pr);
	if (ret == -1)
		MSG(0, "\tprobe of %s failed, cannot detect existing filesystem.\n",
			device);
	return ret;
}

static int f2fs_check_overwrite(void)
{
	int i;

	for (i = 0; i < c.ndevs; i++)
		if (f2fs_dev_is_overwrite((char *)c.devices[i].path))
			return -1;
	return 0;
}

#else

static int f2fs_check_overwrite(void)
{
	return 0;
}

#endif /* HAVE_LIBBLKID */

int main(int argc, char *argv[])
{
	f2fs_init_configuration();

	f2fs_parse_options(argc, argv);

	f2fs_show_info();

	c.func = MKFS;

	if (!force_overwrite && f2fs_check_overwrite()) {
		MSG(0, "\tUse the -f option to force overwrite.\n");
		return -1;
	}

	if (f2fs_devs_are_umounted() < 0) {
		if (errno != EBUSY)
			MSG(0, "\tError: Not available on mounted device!\n");
		return -1;
	}

	if (f2fs_get_device_info() < 0)
		goto err_format;

	/*
	 * Some options are mandatory for host-managed
	 * zoned block devices.
	 */
	if (c.zoned_model == F2FS_ZONED_HM && !c.zoned_mode) {
		MSG(0, "\tError: zoned block device feature is required\n");
		goto err_format;
	}

	if (c.zoned_mode && !c.trim) {
		MSG(0, "\tError: Trim is required for zoned block devices\n");
		goto err_format;
	}

	if (f2fs_format_device() < 0)
		goto err_format;

	if (f2fs_finalize_device() < 0)
		goto err_format;

	MSG(0, "Info: format successful\n");

	return 0;

err_format:
	f2fs_release_sparse_resource();
	return -1;
}
