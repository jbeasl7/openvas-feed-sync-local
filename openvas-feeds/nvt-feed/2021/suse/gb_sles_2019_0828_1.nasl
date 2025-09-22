# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0828.1");
  script_cve_id("CVE-2018-14633", "CVE-2019-2024", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0828-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0828-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190828-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129179");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005273.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0828-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-2024: A use-after-free when disconnecting a source was fixed which could lead to crashes. bnc#1129179).
- CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap minimum address, which made it easier for attackers to exploit kernel NULL pointer dereferences on non-SMAP platforms. This is related to a capability check for the wrong task (bnc#1128166).
- CVE-2018-14633: A security flaw was found in the chap_server_compute_md5() function in the ISCSI target code in the Linux kernel in a way an authentication request from an ISCSI initiator is processed. (bnc#1107829).
- CVE-2019-7221: The KVM implementation in the Linux kernel had a Use-after-Free (bnc#1124732).
- CVE-2019-7222: The KVM implementation in the Linux kernel had an Information Leak (bnc#1124735).
- CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled reference counting because of a race condition, which led to a use-after-free (bnc#1124728).

The following non-security bugs were fixed:

- copy_mount_string: Limit string length to PATH_MAX (bsc#1082943).
- enic: add wq clean up budget (bsc#1075697, bsc#1120691. bsc#1102959).
- ibmvscsi: Fix empty event pool access during host removal (bsc#1119019).
- ipv4: ipv6: Adjust the frag mem limit after truesize has been changed (bsc#1110286).
- kmps: obsolete older KMPs of the same flavour (bsc#1127155, bsc#1109137).
- netfilter: ipv6: Adjust the frag mem limit after truesize has been changed (bsc#1110286).
- perf/x86: Add sysfs entry to freeze counters on SMI (bsc#1121805).
- perf/x86/intel: Delay memory deallocation until x86_pmu_dead_cpu() (bsc#1121805).
- perf/x86/intel: Do not enable freeze-on-smi for PerfMon V1 (bsc#1121805).
- perf/x86/intel: Fix memory corruption (bsc#1121805).
- perf/x86/intel: Generalize dynamic constraint creation (bsc#1121805).
- perf/x86/intel: Implement support for TSX Force Abort (bsc#1121805).
- perf/x86/intel: Make cpuc allocations consistent (bsc#1121805).
- pseries/energy: Use OF accessor function to read ibm,drc-indexes (bsc#1129080).
- restore cond_resched() in shrink_dcache_parent() (bsc#1098599, bsc#1105402, bsc#1127758).
- rps: flow_dissector: Fix uninitialized flow_keys used in __skb_get_hash possibly (bsc#1108145).
- scsi: megaraid_sas: Send SYNCHRONIZE_CACHE for VD to firmware (bsc#1121698).
- scsi: sym53c8xx: fix NULL pointer dereference panic in sym_int_sir() (bsc#1125315).
- x86: Add TSX Force Abort CPUID/MSR (bsc#1121805).
- x86: respect memory size limiting via mem= parameter (bsc#1117645).
- x86/spectre_v2: Do not check microcode versions when running under hypervisors (bsc#1122821).
- x86/xen: dont add memory above max allowed allocation (bsc#1117645).
- xen-netfront: Fix hang on device removal (bnc#1012382).
- xfrm: use complete IPv6 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.104.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_104-default", rpm:"kgraft-patch-4_4_121-92_104-default~1~3.3.1", rls:"SLES12.0SP2"))) {
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
