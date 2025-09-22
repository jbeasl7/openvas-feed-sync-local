# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3484.1");
  script_cve_id("CVE-2020-0430", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-2521", "CVE-2020-25212", "CVE-2020-25285", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 11:55:41 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3484-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3484-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203484-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3484-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bug fixes.


The following security bugs were fixed:

CVE-2020-25705: A flaw in the way reply ICMP packets are limited in was
 found that allowed to quickly scan open UDP ports. This flaw allowed an
 off-path remote user to effectively bypassing source port UDP
 randomization. The highest threat from this vulnerability is to
 confidentiality and possibly integrity, because software and services
 that rely on UDP source port randomization (like DNS) are indirectly
 affected as well. Kernel versions may be vulnerable to this issue
 (bsc#1175721, bsc#1178782).

CVE-2020-8694: Insufficient access control for some Intel(R) Processors
 may have allowed an authenticated user to potentially enable information
 disclosure via local access (bsc#1170415).

CVE-2020-25668: Fixed a use-after-free in con_font_op() (bsc#1178123).

CVE-2020-25704: Fixed a memory leak in perf_event_parse_addr_filter()
 (bsc#1178393).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

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

CVE-2020-12351: Implemented a kABI workaround for bluetooth l2cap_ops
 filter addition (bsc#1177724).

CVE-2020-12352: Fixed an information leak when processing certain AMP
 packets aka 'BleedingTooth' (bsc#1177725).

CVE-2020-25212: Fixed a TOCTOU mismatch in the NFS client code
 (bnc#1176381).

CVE-2020-25645: Fixed an issue in IPsec that caused traffic between
 two Geneve endpoints to be unencrypted (bnc#1177511).

The following non-security bugs were fixed:

9P: Cast to loff_t before multiplying (git-fixes).

acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (git-fixes).

ACPI: debug: do not allow debugging when ACPI is disabled (git-fixes).

ACPI: dock: fix enum-conversion warning (git-fixes).

ACPI / extlog: Check for RDMSR failure (git-fixes).

ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

ACPI: video: use ACPI backlight for HP 635 Notebook (git-fixes).

ALSA: bebob: potential info leak in hwdep_read() (git-fixes).

ALSA: compress_offload: remove redundant initialization (git-fixes).

ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: core: pcm: simplify locking for timers (git-fixes).

ALSA: core: timer: clarify operator precedence (git-fixes).

ALSA: core: timer: remove redundant assignment (git-fixes).

ALSA: ctl: Workaround for lockdep warning wrt card->ctl_files_rwlock
 (git-fixes).

ALSA: hda: auto_parser: remove ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.52.1", rls:"SLES15.0SP1"))) {
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
