# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1289.1");
  script_cve_id("CVE-2016-10741", "CVE-2017-1000407", "CVE-2017-16533", "CVE-2017-7273", "CVE-2017-7472", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-14633", "CVE-2018-15572", "CVE-2018-16884", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-5391", "CVE-2018-9516", "CVE-2018-9568", "CVE-2019-11091", "CVE-2019-11486", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3882", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-8564", "CVE-2019-9213", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:12 +0000 (Wed, 29 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1289-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191289-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133188");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-May/005476.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive various security and bugfixes.

Four new speculative execution information leak issues have been identified in Intel CPUs. (bsc#1111331)

- CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)
- CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)
- CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)
- CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory (MDSUM)

This kernel update contains software mitigations for these issues, which also utilize CPU microcode updates shipped in parallel.

For more information on this set of information leaks, check out [link moved to references]

The following security bugs were fixed:

- CVE-2016-10741: fs/xfs/xfs_aops.c allowed local users to cause a denial of service (system crash) because there is a race condition between direct and memory-mapped I/O (associated with a hole) that is handled with BUG_ON instead of an I/O failure (bnc#1114920 bnc#1124010).
- CVE-2017-1000407: By flooding the diagnostic port 0x80 an exception can be triggered leading to a kernel panic (bnc#1071021).
- CVE-2017-16533: The usbhid_parse function in drivers/hid/usbhid/hid-core.c allowed local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066674).
- CVE-2017-7273: The cp_report_fixup function in drivers/hid/hid-cypress.c allowed physically proximate attackers to cause a denial of service (integer underflow) or possibly have unspecified other impact via a crafted HID report (bnc#1031240).
- CVE-2017-7472: The KEYS subsystem allowed local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls (bnc#1034862).
- CVE-2018-14633: A security flaw was found in the chap_server_compute_md5() function in the ISCSI target code in the Linux kernel in a way an authentication request from an ISCSI initiator is processed. An unauthenticated remote attacker can cause a stack buffer overflow and smash up to 17 bytes of the stack. The attack requires the iSCSI target to be enabled on the victim host. Depending on how the target's code was built (i.e. depending on a compiler, compile flags and hardware architecture) an attack may lead to a system crash and thus to a denial-of-service or possibly to a non-authorized access to data exported by an iSCSI target. (bnc#1107829).
- CVE-2018-15572: The spectre_v2_select_mitigation function in arch/x86/kernel/cpu/bugs.c did not always fill RSB upon a context switch, which made it easier for attackers to conduct userspace-userspace spectreRSB attacks (bnc#1102517 bnc#1105296).
- CVE-2018-16884: NFS41+ shares mounted in different network namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.110.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.110.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_110-default", rpm:"kgraft-patch-3_12_74-60_64_110-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_110-xen", rpm:"kgraft-patch-3_12_74-60_64_110-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.7.0~4.4.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.7.0_k3.12.74_60.64.110~4.4.1", rls:"SLES12.0SP1"))) {
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
