# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0658.1");
  script_cve_id("CVE-2015-0777", "CVE-2015-2150");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0658-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0658-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150658-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924460");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001326.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security Update for Linux Kernel' package(s) announced via the SUSE-SU-2015:0658-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 12 kernel was updated to 3.12.39 to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2015-0777: The XEN usb backend could leak information to the guest
 system due to copying uninitialized memory.

- CVE-2015-2150: Xen and the Linux kernel did not properly restrict access
 to PCI command registers, which might have allowed local guest users to
 cause a denial of service (non-maskable interrupt and host crash) by
 disabling the (1) memory or (2) I/O decoding for a PCI Express device
 and then accessing the device, which triggers an Unsupported Request
 (UR) response.

The following non-security bugs were fixed:
- Added Little Endian support to vtpm module (bsc#918620).
- Add support for pnfs block layout. Patches not included by default yet
- ALSA: hda - Fix regression of HD-audio controller fallback modes (bsc#921313).
- btrfs: add missing blk_finish_plug in btrfs_sync_log() (bnc#922284).
- btrfs: cleanup orphans while looking up default subvolume (bsc#914818).
- btrfs: do not ignore errors from btrfs_lookup_xattr in do_setxattr (bnc#922272).
- btrfs: fix BUG_ON in btrfs_orphan_add() when delete unused block group (bnc#922278).
- btrfs: fix data loss in the fast fsync path (bnc#922275).
- btrfs: fix fsync data loss after adding hard link to inode (bnc#922275).
- cgroup: revert cgroup_mutex removal from idr_remove (bnc#918644).
- cifs: fix use-after-free bug in find_writable_file (bnc#909477).
- crypto: rng - RNGs must return 0 in success case (bsc#920805).
- crypto: testmgr - fix RNG return code enforcement (bsc#920805).
- exit: Always reap resource stats in __exit_signal() (Time scalability).
- fork: report pid reservation failure properly (bnc#909684).
- fsnotify: Fix handling of renames in audit (bnc#915200).
- HID: hyperv: match wait_for_completion_timeout return type.
- hv: address compiler warnings for hv_fcopy_daemon.c.
- hv: address compiler warnings for hv_kvp_daemon.c.
- hv: check vmbus_device_create() return value in vmbus_process_offer().
- hv: do not add redundant / in hv_start_fcopy().
- hv: hv_balloon: Do not post pressure status from interrupt context.
- hv: hv_balloon: Fix a locking bug in the balloon driver.
- hv: hv_balloon: Make adjustments in computing the floor.
- hv: hv_fcopy: drop the obsolete message on transfer failure.
- hv: kvp_daemon: make IPv6-only-injection work.
- hv: remove unused bytes_written from kvp_update_file().
- hv: rename sc_lock to the more generic lock.
- hv: vmbus: Fix a bug in vmbus_establish_gpadl().
- hv: vmbus: hv_process_timer_expiration() can be static.
- hv: vmbus: Implement a clockevent device.
- hv: vmbus: serialize Offer and Rescind offer.
- hv: vmbus: Support a vmbus API for efficiently sending page arrays.
- hv: vmbus: Use get_cpu() to get the current CPU.
- hyperv: fix sparse warnings.
- hyperv: Fix the error processing in netvsc_send().
- hyperv: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Security Update for Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.39~47.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
