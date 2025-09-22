# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2949.1");
  script_cve_id("CVE-2016-10906", "CVE-2017-18379", "CVE-2017-18509", "CVE-2017-18551", "CVE-2017-18595", "CVE-2018-12207", "CVE-2018-20976", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-13272", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15098", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-15666", "CVE-2019-15807", "CVE-2019-15902", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16413", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-9456", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 14:31:27 +0000 (Thu, 10 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2949-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2949-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192949-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1147022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1147122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155671");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006110.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023735");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7024251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2949-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12-SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a race
 condition in the Instruction Fetch Unit of the Intel CPU to cause a Machine
 Exception during Page Size Change, causing the CPU core to be non-functional.

 The Linux Kernel kvm hypervisor was adjusted to avoid page size changes in
 executable pages by splitting / merging huge pages into small pages as
 needed. More information can be found on [link moved to references]

- CVE-2019-16995: Fix a memory leak in hsr_dev_finalize() if hsr_add_port
 failed to add a port, which may have caused denial of service (bsc#1152685).

- CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs with
 Transactional Memory support could be used to facilitate sidechannel
 information leaks out of microarchitectural buffers, similar to the
 previously described 'Microarchitectural Data Sampling' attack.

 The Linux kernel was supplemented with the option to disable TSX operation
 altogether (requiring CPU Microcode updates on older systems) and better
 flushing of microarchitectural buffers (VERW).

 The set of options available is described in our TID at [link moved to references]

- CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return value, leading to a NULL pointer dereference.
 (bsc#1150457).

- CVE-2019-10220: Added sanity checks on the pathnames passed to the user
 space. (bsc#1144903).

- CVE-2019-17666: rtlwifi: Fix potential overflow in P2P code (bsc#1154372).

- CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID IE,
 leading to a Buffer Overflow (bsc#1153158).

- CVE-2019-16232: Fix a potential NULL pointer dereference in the Marwell
 libertas driver (bsc#1150465).

- CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue return
 value, leading to a NULL pointer dereference. (bsc#1150452).

- CVE-2019-17055: The AF_ISDN network module in the Linux kernel did not
 enforce CAP_NET_RAW, which meant that unprivileged users could create a raw
 socket (bnc#1152782).

- CVE-2019-17056: The AF_NFC network module did not enforce CAP_NET_RAW, which
 meant that unprivileged users could create a raw socket (bsc#1152788).

- CVE-2019-16413: The 9p filesystem did not protect i_size_write() properly,
 which caused an i_size_read() infinite loop and denial of service on SMP
 systems (bnc#1151347).

- CVE-2019-15902: A backporting issue was discovered that re-introduced the
 Spectre vulnerability it had aimed to eliminate. This occurred because the
 backport process depends on cherry picking specific commits, and because two
 (correctly ordered) code lines were swapped (bnc#1149376).

- CVE-2019-15291: Fixed a NULL pointer dereference issue that could be caused
 by a malicious USB device ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.107.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_107-default", rpm:"kgraft-patch-4_4_180-94_107-default~1~4.3.1", rls:"SLES12.0SP3"))) {
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
