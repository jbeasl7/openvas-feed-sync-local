# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3273.1");
  script_cve_id("CVE-2020-25656", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-11-02 14:44:50 +0000 (Tue, 02 Nov 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 17:04:20 +0000 (Fri, 20 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3273-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203273-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bug fixes.


The following security bugs were fixed:

CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl
 (bnc#1177766).

CVE-2020-8694: Restricted energy meter to root access (bsc#1170415).

The following non-security bugs were fixed:

act_ife: load meta modules before tcf_idr_check_alloc()
 (networking-stable-20_09_24).

ath10k: check idx validity in __ath10k_htt_rx_ring_fill_n() (git-fixes).

ath9k: hif_usb: fix race condition between usb_get_urb() and
 usb_kill_anchored_urbs() (git-fixes).

block: Set same_page to false in __bio_try_merge_page if ret is false
 (git-fixes).

Bluetooth: btusb: Fix memleak in btusb_mtk_submit_wmt_recv_urb
 (git-fixes).

Bluetooth: Only mark socket zapped after unlocking (git-fixes).

bnxt_en: Protect bnxt_set_eee() and bnxt_set_pauseparam() with mutex
 (git-fixes).

bonding: show saner speed for broadcast mode
 (networking-stable-20_08_24).

brcm80211: fix possible memleak in brcmf_proto_msgbuf_attach (git-fixes).

brcmsmac: fix memory leak in wlc_phy_attach_lcnphy (git-fixes).

btrfs: allocate scrub workqueues outside of locks (bsc#1178183).

btrfs: do not force read-only after error in drop snapshot (bsc#1176354).

btrfs: drop path before adding new uuid tree entry (bsc#1178176).

btrfs: fix filesystem corruption after a device replace (bsc#1178395).

btrfs: fix NULL pointer dereference after failure to create snapshot
 (bsc#1178190).

btrfs: fix overflow when copying corrupt csums for a message
 (bsc#1178191).

btrfs: fix space cache memory leak after transaction abort (bsc#1178173).

btrfs: move btrfs_rm_dev_replace_free_srcdev outside of all locks
 (bsc#1178395).

btrfs: move btrfs_scratch_superblocks into btrfs_dev_replace_finishing
 (bsc#1178395).

btrfs: set the correct lockdep class for new nodes (bsc#1178184).

btrfs: set the lockdep class for log tree extent buffers (bsc#1178186).

can: flexcan: flexcan_chip_stop(): add error handling and propagate
 error value (git-fixes).

ceph: promote to unsigned long long before shifting (bsc#1178175).

crypto: ccp - fix error handling (git-fixes).

cxgb4: fix memory leak during module unload (networking-stable-20_09_24).

cxgb4: Fix offset when clearing filter byte counters
 (networking-stable-20_09_24).

Disable ipa-clones dump for KMP builds (bsc#1178330) The feature is not
 really useful for KMP, and rather confusing, so let's disable it at
 building out-of-tree codes

Disable module compression on SLE15 SP2 (bsc#1178307)

dmaengine: dw: Activate FIFO-mode for memory peripherals only
 (git-fixes).

eeprom: at25: set minimum read/write access stride to 1 (git-fixes).

futex: Adjust absolute futex timeouts with per time namespace offset
 (bsc#1164648).

futex: Consistently use fshared as boolean (bsc#1149032).

futex: Fix incorrect should_fail_futex() handling (bsc#1149032).

futex: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.37.1.9.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.37.1", rls:"SLES15.0SP2"))) {
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
