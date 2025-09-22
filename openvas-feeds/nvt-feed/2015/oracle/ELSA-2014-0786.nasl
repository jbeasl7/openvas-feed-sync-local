# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123354");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0206", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2568", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:40 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:17:50 +0000 (Tue, 02 Jul 2024)");

  script_name("Oracle: Security Advisory (ELSA-2014-0786)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0786");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0786.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-0786 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.4.2]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.4.2]
- [fs] aio: fix plug memory disclosure and fix reqs_active accounting backport (Jeff Moyer) [1094604 1094605] {CVE-2014-0206}
- [fs] aio: plug memory disclosure and fix reqs_active accounting (Mateusz Guzik) [1094604 1094605] {CVE-2014-0206}

[3.10.0-123.4.1]
- [kernel] futex: Make lookup_pi_state more robust (Larry Woodman) [1104519 1104520] {CVE-2014-3153}
- [kernel] futex: Always cleanup owner tid in unlock_pi (Larry Woodman) [1104519 1104520] {CVE-2014-3153}
- [kernel] futex: Validate atomic acquisition in futex_lock_pi_atomic() (Larry Woodman) [1104519 1104520] {CVE-2014-3153}
- [kernel] futex: prevent requeue pi on same futex (Larry Woodman) [1104519 1104520] {CVE-2014-3153}
- [ethernet] qlcnic: Fix ethtool statistics length calculation (Michal Schmidt) [1104972 1099634]
- Revert: [kernel] cputime: Default implementation of nsecs -> cputime conversion (Frederic Weisbecker) [1090974 1047732]
- Revert: [kernel] cputime: Bring cputime -> nsecs conversion (Frederic Weisbecker) [1090974 1047732]
- Revert: [kernel] cputime: Fix jiffies based cputime assumption on steal accounting (Frederic Weisbecker) [1090974 1047732]

[3.10.0-123.3.1]
- [kernel] mutexes: Give more informative mutex warning in the !lock->owner case (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] mutex: replace CONFIG_HAVE_ARCH_MUTEX_CPU_RELAX with simple ifdef (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutexes: Introduce cancelable MCS lock for adaptive spinning (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutexes: Modify the way optimistic spinners are queued (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutexes: Return false if task need_resched() in mutex_can_spin_on_owner() (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] Restructure the MCS lock defines and locking & Move mcs_spinlock.h into kernel/locking/ (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [misc] arch: Introduce smp_load_acquire(), smp_store_release() (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutex: Fix debug_mutexes (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutex: Fix debug checks (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]
- [kernel] locking/mutexes: Unlock the mutex without the wait_lock (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]

[3.10.0-123.2.1]
- [net] filter: prevent nla extensions to peek beyond the end of the message (Jiri Benc) [1096780 1096781] {CVE-2014-3144 CVE-2014-3145}
- [block] floppy: don't write kernel-only members to FDRAWCMD ioctl output (Denys Vlasenko) [1094316 1094318] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.4.2.el7", rls:"OracleLinux7"))) {
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
