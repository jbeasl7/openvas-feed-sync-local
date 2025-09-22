# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3122.1");
  script_cve_id("CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25285");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:05:31 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3122-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203122-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-25285: A race condition between hugetlb sysctl handlers in
 mm/hugetlb.c could be used by local attackers to corrupt memory, cause a
 NULL pointer dereference, or possibly have unspecified other impact
 (bnc#1176485).

CVE-2020-16120: Fixed permission check to open real file when using
 overlayfs. It was possible to have a file not readable by an
 unprivileged user be copied to a mountpoint controlled by that user and
 then be able to access the file. (bsc#1177470)

CVE-2020-14351: Fixed a race condition in the perf_mmap_close() function
 (bsc#1177086).

The following non-security bugs were fixed:

ACPI: Always build evged in (git-fixes).

ACPI: button: fix handling lid state changes when input device closed
 (git-fixes).

ACPI: configfs: Add missing config_item_put() to fix refcount leak
 (git-fixes).

acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (git-fixes).

ACPI: debug: do not allow debugging when ACPI is disabled (git-fixes).

Add CONFIG_CHECK_CODESIGN_EKU

ALSA: ac97: (cosmetic) align argument names (git-fixes).

ALSA: aoa: i2sbus: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: asihpi: fix spellint typo in comments (git-fixes).

ALSA: atmel: ac97: clarify operator precedence (git-fixes).

ALSA: bebob: potential info leak in hwdep_read() (git-fixes).

ALSA: compress_offload: remove redundant initialization (git-fixes).

ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: core: pcm: simplify locking for timers (git-fixes).

ALSA: core: timer: clarify operator precedence (git-fixes).

ALSA: core: timer: remove redundant assignment (git-fixes).

ALSA: ctl: Workaround for lockdep warning wrt card->ctl_files_rwlock
 (git-fixes).

ALSA: fireworks: use semicolons rather than commas to separate
 statements (git-fixes).

ALSA: hda: auto_parser: remove shadowed variable declaration (git-fixes).

ALSA: hda: (cosmetic) align function parameters (git-fixes).

ALSA: hda - Do not register a cb func if it is registered already
 (git-fixes).

ALSA: hda - Fix the return value if cb func is already registered
 (git-fixes).

ALSA: hda/hdmi: fix incorrect locking in hdmi_pcm_close (git-fixes).

ALSA: hda/realtek - Add mute Led support for HP Elitebook 845 G7
 (git-fixes).

ALSA: hda/realtek: Enable audio jacks of ASUS D700SA with ALC887
 (git-fixes).

ALSA: hda/realtek - set mic to auto detect on a HP AIO machine
 (git-fixes).

ALSA: hda/realtek - The front Mic on a HP machine does not work
 (git-fixes).

ALSA: hda: use semicolons rather than commas to separate statements
 (git-fixes).

ALSA: hdspm: Fix typo arbitrary (git-fixes).

ALSA: mixart: Correct comment wrt obsoleted tasklet usage (git-fixes).

ALSA: portman2x4: fix repeated word 'if' (git-fixes).

ALSA: rawmidi: (cosmetic) align function ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.34.1.9.11.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.34.1", rls:"SLES15.0SP2"))) {
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
