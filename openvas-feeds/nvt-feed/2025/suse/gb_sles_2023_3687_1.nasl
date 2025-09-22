# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3687.1");
  script_cve_id("CVE-2022-36402", "CVE-2023-2007", "CVE-2023-20588", "CVE-2023-21400", "CVE-2023-3772", "CVE-2023-3863", "CVE-2023-4128", "CVE-2023-4132", "CVE-2023-4134", "CVE-2023-4273", "CVE-2023-4385", "CVE-2023-4387", "CVE-2023-4459");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-04 18:24:30 +0000 (Thu, 04 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3687-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3687-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233687-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214451");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-September/016222.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3687-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-2007: Fixed a flaw in the DPT I2O Controller driver that could allow an attacker to escalate privileges and execute arbitrary code in the context of the kernel (bsc#1210448).
- CVE-2023-3772: Fixed a flaw in XFRM subsystem that may have allowed a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer leading to a possible kernel crash and denial of service (bsc#1213666).
- CVE-2023-3863: Fixed a use-after-free flaw was found in nfc_llcp_find_local that allowed a local user with special privileges to impact a kernel information leak issue (bsc#1213601).
- CVE-2023-4128: Fixed a use-after-free flaw in net/sched/cls_fw.c that allowed a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue (bsc#1214149).
- CVE-2023-4132: Fixed use-after-free vulnerability was found in the siano smsusb module that allowed a local user to crash the system, causing a denial of service condition (bsc#1213969).
- CVE-2023-4134: Fixed use-after-free in cyttsp4_watchdog_work() (bsc#1213971).
- CVE-2023-4273: Fixed a flaw in the exFAT driver of the Linux kernel that alloawed a local privileged attacker to overflow the kernel stack (bsc#1214120).
- CVE-2023-4385: Fixed a NULL pointer dereference flaw in dbFree that may have allowed a local attacker to crash the system due to a missing sanity check (bsc#1214348).
- CVE-2023-4387: Fixed use-after-free flaw in vmxnet3_rq_alloc_rx_buf that could allow a local attacker to crash the system due to a double-free (bsc#1214350).
- CVE-2023-4459: Fixed a NULL pointer dereference flaw in vmxnet3_rq_cleanup that may have allowed a local attacker with normal user privilege to cause a denial of service (bsc#1214451).
- CVE-2022-36402: Fixed an integer overflow vulnerability in vmwgfx driver in that allowed a local attacker with a user account on the system to gain privilege, causing a denial of service (bsc#1203517).
- CVE-2023-20588: Fixed a division-by-zero error on some AMD processors that can potentially return speculative data resulting in loss of confidentiality (bsc#1213927).
- CVE-2023-21400: Fixed several memory corruptions due to improper locking in io_uring (bsc#1213272).


The following non-security bugs were fixed:

- kabi/severities: Ignore newly added SRSO mitigation functions
- x86/cpu/kvm: Provide UNTRAIN_RET_VM (git-fixes).
- x86/cpu: Cleanup the untrain mess (git-fixes).
- x86/cpu: Rename original retbleed methods (git-fixes).
- x86/cpu: Rename srso_(.*)_alias to srso_alias_\1 (git-fixes).
- x86/retpoline: Do not clobber RFLAGS during srso_safe_ret() (git-fixes).
- x86/speculation: Add cpu_show_gds() prototype (git-fixes).
- x86/speculation: Mark all Skylake CPUs as vulnerable to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.163.1.150200.9.81.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.163.1", rls:"SLES15.0SP2"))) {
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
