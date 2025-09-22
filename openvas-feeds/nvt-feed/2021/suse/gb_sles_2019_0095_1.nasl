# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0095.1");
  script_cve_id("CVE-2018-10940", "CVE-2018-14613", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-16276", "CVE-2018-16597", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-9516");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 14:24:35 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0095-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190095-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997172");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-January/005035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 Azure kernel was updated to 4.4.162 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping pagetable locks. If a syscall such as ftruncate() removes entries from the pagetables of a task that is in the middle of mremap(), a stale TLB entry can remain for a short time that permits access to a physical page after it has been released back to the page allocator and reused. (bnc#1113769).
- CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from unsigned long to int interferes with bounds checking. This is similar to CVE-2018-10940 and CVE-2018-16658 (bnc#1113751).
- CVE-2018-18690: A local attacker able to set attributes on an xfs filesystem could make this filesystem non-operational until the next mount by triggering an unchecked error condition during an xfs attribute change, because xfs_attr_shortform_addname in fs/xfs/libxfs/xfs_attr.c mishandled ATTR_REPLACE operations with conversion of an attr from short to long form (bnc#1105025).
- CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are able to access pseudo terminals) to hang/block further usage of any pseudo terminal devices due to an EXTPROC versus ICANON confusion in TIOCINQ (bnc#1094825).
- CVE-2018-9516: In hid_debug_events_read of drivers/hid/hid-debug.c, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. (bnc#1108498).
- CVE-2018-14633: A security flaw was found in the chap_server_compute_md5() function in the ISCSI target code in a way an authentication request from an ISCSI initiator is processed. An unauthenticated remote attacker can cause a stack buffer overflow and smash up to 17 bytes of the stack. The attack requires the iSCSI target to be enabled on the victim host. Depending on how the target's code was built (i.e. depending on a compiler, compile flags and hardware architecture) an attack may lead to a system crash and thus to a denial-of-service or possibly to a non-authorized access to data exported by an iSCSI target. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is highly unlikely. (bnc#1107829).
- CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c mishandled sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations (bnc#1108399).
- CVE-2018-16597: Incorrect access checking in overlayfs mounts could be used by local attackers to modify or truncate files in the underlying filesystem ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.4.162~4.19.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.4.162~4.19.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.4.162~4.19.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.4.162~4.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.4.162~4.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.4.162~4.19.1", rls:"SLES12.0SP3"))) {
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
