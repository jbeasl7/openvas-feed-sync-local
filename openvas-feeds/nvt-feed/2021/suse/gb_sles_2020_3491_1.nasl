# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3491.1");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-24490", "CVE-2020-25212", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25705", "CVE-2020-27673", "CVE-2020-27675");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:14:46 +0000 (Mon, 30 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3491-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3491-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203491-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3491-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl
 (bnc#1177766).

CVE-2020-25285: Fixed a race condition between hugetlb sysctl handlers
 in mm/hugetlb.c (bnc#1176485).

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

CVE-2020-24490: Fixed a heap buffer overflow when processing extended
 advertising report events aka 'BleedingTooth' aka 'BadVibes'
 (bsc#1177726).

CVE-2020-25641: Fixed a zero-length biovec request issued by the block
 subsystem could have caused the kernel to enter an infinite loop,
 causing a denial of service (bsc#1177121).

CVE-2020-25643: Fixed a memory corruption and a read overflow which
 could have caused by improper input validation in the ppp_cp_parse_cr
 function (bsc#1177206).

CVE-2020-27673: Fixed an issue where rogue guests could have caused
 denial of service of Dom0 via high frequency events (XSA-332 bsc#1177411)

CVE-2020-27675: Fixed a race condition in event handler which may crash
 dom0 (XSA-331 bsc#1177410).

CVE-2020-25705: A ICMP global rate limiting side-channel was removed
 which could lead to e.g. the SADDNS attack (bsc#1175721)

The following non-security bugs were fixed:

9p: Fix memory leak in v9fs_mount (git-fixes).

ACPI: Always build evged in (git-fixes).

ACPI: button: fix handling lid state changes when input device closed
 (git-fixes).

ACPI: configfs: Add missing config_item_put() to fix refcount leak
 (git-fixes).

acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (git-fixes).

ACPI: debug: do not allow debugging when ACPI is disabled (git-fixes).

ACPI: EC: Reference count query handlers under lock (git-fixes).

act_ife: load meta modules before tcf_idr_check_alloc()
 (networking-stable-20_09_24).

Add CONFIG_CHECK_CODESIGN_EKU

airo: Fix read overflows sending packets (git-fixes).

ALSA: ac97: (cosmetic) align argument names (git-fixes).

ALSA: aoa: i2sbus: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).

ALSA: asihpi: fix spellint typo in comments (git-fixes).

ALSA: atmel: ac97: clarify operator precedence (git-fixes).

ALSA: bebob: potential info leak in hwdep_read() (git-fixes).

ALSA: compress_offload: remove redundant initialization (git-fixes).

ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.24.1", rls:"SLES15.0SP2"))) {
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
