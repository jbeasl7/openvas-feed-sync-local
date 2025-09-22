# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2776.1");
  script_cve_id("CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10902", "CVE-2018-10938", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-9363");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 22:07:35 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2776-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182776-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970506");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004572.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2776-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.155 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-13093: Prevent NULL pointer dereference and panic in lookup_slow()
 on a NULL inode->i_ops pointer when doing pathwalks on a corrupted xfs image.
 This occurred because of a lack of proper validation that cached inodes are free
 during allocation (bnc#1100001).
- CVE-2018-13095: Prevent denial of service (memory corruption and BUG) that
 could have occurred for a corrupted xfs image upon encountering an inode that
 is in extent format, but has more extents than fit in the inode fork
 (bnc#1099999).
- CVE-2018-13094: Prevent OOPS that may have occurred for a corrupted xfs image
 after xfs_da_shrink_inode() is called with a NULL bp (bnc#1100000).
- CVE-2018-12896: Prevent integer overflow in the POSIX timer code that was
 caused by the way the overrun accounting works. Depending on interval and
 expiry time values, the overrun can be larger than INT_MAX, but the accounting
 is int based. This basically made the accounting values, which are visible to
 user space via timer_getoverrun(2) and siginfo::si_overrun, random. This
 allowed a local user to cause a denial of service (signed integer overflow) via
 crafted mmap, futex, timer_create, and timer_settime system calls
 (bnc#1099922).
- CVE-2018-16658: Prevent information leak in cdrom_ioctl_drive_status that
 could have been used by local attackers to read kernel memory (bnc#1107689).
- CVE-2018-6555: The irda_setsockopt function allowed local users to cause a
 denial of service (ias_object use-after-free and system crash) or possibly have
 unspecified other impact via an AF_IRDA socket (bnc#1106511).
- CVE-2018-6554: Prevent memory leak in the irda_bind function that allowed
 local users to cause a denial of service (memory consumption) by repeatedly
 binding an AF_IRDA socket (bnc#1106509).
- CVE-2018-1129: A flaw was found in the way signature calculation was handled
 by cephx authentication protocol. An attacker having access to ceph cluster
 network who is able to alter the message payload was able to bypass signature
 checks done by cephx protocol (bnc#1096748).
- CVE-2018-1128: It was found that cephx authentication protocol did not verify
 ceph clients correctly and was vulnerable to replay attack. Any attacker having
 access to ceph cluster network who is able to sniff packets on network can use
 this vulnerability to authenticate with ceph service and perform actions
 allowed by ceph service (bnc#1096748).
- CVE-2018-10938: A crafted network packet sent remotely by an attacker forced
 the kernel to enter an infinite loop in the cipso_v4_optptr() function leading
 to a denial-of-service (bnc#1106016).
- CVE-2018-15572: The spectre_v2_select_mitigation function did not always fill
 RSB upon a context switch, which made it easier for attackers to conduct
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.155~94.50.1", rls:"SLES12.0SP3"))) {
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
