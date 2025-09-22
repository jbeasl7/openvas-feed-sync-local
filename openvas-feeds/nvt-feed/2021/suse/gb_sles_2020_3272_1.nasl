# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3272.1");
  script_cve_id("CVE-2020-0430", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25285", "CVE-2020-25656", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:05:31 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3272-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203272-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bug fixes.


The following security bugs were fixed:

CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl
 (bnc#1177766).

CVE-2020-25285: Fixed a race condition between hugetlb sysctl handlers
 in mm/hugetlb.c (bnc#1176485).

CVE-2020-0430: Fixed an OOB read in skb_headlen of
 /include/linux/skbuff.h (bnc#1176723).

CVE-2020-14351: Fixed a race in the perf_mmap_close() function
 (bsc#1177086).

CVE-2020-16120: Fixed a permissions issue in ovl_path_open()
 (bsc#1177470).

CVE-2020-8694: Restricted energy meter to root access (bsc#1170415).

CVE-2020-27673: Fixed an issue where rogue guests could have caused
 denial of service of Dom0 via high frequency events (XSA-332 bsc#1177411)

CVE-2020-27675: Fixed a race condition in event handler which may crash
 dom0 (XSA-331 bsc#1177410).

The following non-security bugs were fixed:

ALSA: bebob: potential info leak in hwdep_read() (git-fixes).

ALSA: compress_offload: remove redundant initialization (git-fixes).

ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: core: pcm: simplify locking for timers (git-fixes).

ALSA: core: timer: clarify operator precedence (git-fixes).

ALSA: core: timer: remove redundant assignment (git-fixes).

ALSA: ctl: Workaround for lockdep warning wrt card->ctl_files_rwlock
 (git-fixes).

ALSA: hda - Do not register a cb func if it is registered already
 (git-fixes).

ALSA: hda/realtek - Add mute Led support for HP Elitebook 845 G7
 (git-fixes).

ALSA: hda/realtek - The front Mic on a HP machine does not work
 (git-fixes).

ALSA: hda/realtek: Enable audio jacks of ASUS D700SA with ALC887
 (git-fixes).

ALSA: hda: auto_parser: remove shadowed variable declaration (git-fixes).

ALSA: hda: use semicolons rather than commas to separate statements
 (git-fixes).

ALSA: mixart: Correct comment wrt obsoleted tasklet usage (git-fixes).

ALSA: rawmidi: (cosmetic) align function parameters (git-fixes).

ALSA: seq: oss: Avoid mutex lock for a long-time ioctl (git-fixes).

ALSA: usb-audio: Add mixer support for Pioneer DJ DJM-250MK2 (git-fixes).

ALSA: usb-audio: endpoint.c: fix repeated word 'there' (git-fixes).

ALSA: usb-audio: fix spelling mistake 'Frequence' -> 'Frequency'
 (git-fixes).

ASoC: qcom: lpass-cpu: fix concurrency issue (git-fixes).

ASoC: qcom: lpass-platform: fix memory leak (git-fixes).

ath10k: check idx validity in __ath10k_htt_rx_ring_fill_n() (git-fixes).

ath10k: Fix the size used in a 'dma_free_coherent()' call in an error
 handling path (git-fixes).

ath10k: provide survey info as accumulated data (git-fixes).

ath6kl: prevent potential array overflow in ath6kl_add_new_sta()
 (git-fixes).

ath9k: Fix potential out of bounds in ath9k_htc_txcompletion_cb()
 (git-fixes).

ath9k: hif_usb: fix race condition between usb_get_urb() and
 usb_kill_anchored_urbs() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.67.1", rls:"SLES15.0SP1"))) {
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
