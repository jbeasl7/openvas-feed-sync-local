# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2104.1");
  script_cve_id("CVE-2019-19377", "CVE-2020-26541", "CVE-2021-20321", "CVE-2021-33061", "CVE-2022-0168", "CVE-2022-1011", "CVE-2022-1158", "CVE-2022-1184", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1966", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-28893", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-17 04:28:40 +0000 (Fri, 17 Jun 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-20 17:33:49 +0000 (Fri, 20 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2104-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222104-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200249");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-June/011302.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2104-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated.

The following security bugs were fixed:

- CVE-2022-0168: Fixed a NULL pointer dereference in smb2_ioctl_query_info. (bsc#1197472)
- CVE-2022-1966: Fixed an use-after-free bug in the netfilter subsystem. This flaw allowed a local attacker with user access to cause a privilege escalation issue. (bnc#1200015)
- CVE-2022-28893: Ensuring that sockets are in the intended state inside the SUNRPC subsystem (bnc#1198330).
- CVE-2022-1158: Fixed KVM x86/mmu compare-and-exchange of gPTE via the user address (bsc#1197660).
- CVE-2022-21127: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21123: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21125: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21180: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21166: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-1975: Fixed a bug that allows an attacker to crash the linux kernel by simulating nfc device from user-space. (bsc#1200143)
- CVE-2022-1974: Fixed an use-after-free that could causes kernel crash by simulating an nfc device from user-space. (bsc#1200144)
- CVE-2020-26541: Enforce the secure boot forbidden signature database (aka dbx) protection mechanism. (bnc#1177282)
- CVE-2019-19377: Fixed an user-after-free that could be triggered when an attacker mounts a crafted btrfs filesystem image. (bnc#1158266)
- CVE-2022-1729: Fixed a sys_perf_event_open() race condition against self (bsc#1199507).
- CVE-2022-1184: Fixed an use-after-free and memory errors in ext4 when mounting and operating on a corrupted image. (bsc#1198577)
- CVE-2022-1652: Fixed a statically allocated error counter inside the floppy kernel module (bsc#1199063).
- CVE-2022-1734: Fixed a r/w use-after-free when non synchronized between cleanup routine and firmware download routine. (bnc#1199605)
- CVE-2022-30594: Fixed restriction bypass on setting the PT_SUSPEND_SECCOMP flag (bnc#1199505).
- CVE-2021-33061: Fixed insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters that may have allowed an authenticated user to potentially enable denial of service via local access (bnc#1196426).
- CVE-2022-1516: Fixed null-ptr-deref caused by x25_disconnect (bsc#1199012).
- CVE-2021-20321: Fixed a race condition accessing file object in the OverlayFS subsystem in the way users do rename in specific way ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.115.1.150200.9.54.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.115.1", rls:"SLES15.0SP2"))) {
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
