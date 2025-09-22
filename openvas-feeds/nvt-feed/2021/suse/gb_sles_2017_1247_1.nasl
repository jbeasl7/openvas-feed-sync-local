# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1247.1");
  script_cve_id("CVE-2015-1350", "CVE-2016-10044", "CVE-2016-10200", "CVE-2016-10208", "CVE-2016-2117", "CVE-2016-3070", "CVE-2016-5243", "CVE-2016-7117", "CVE-2016-9588", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-28 15:47:44 +0000 (Tue, 28 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1247-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171247-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989056");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002857.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2015-1350: The VFS subsystem in the Linux kernel provided an incomplete set of requirements for setattr operations that underspecifies removing extended privilege attributes, which allowed local users to cause a denial of service (capability stripping) via a failed invocation of a system call, as demonstrated by using chown to remove a capability from the ping or Wireshark dumpcap program (bnc#914939).
- CVE-2016-2117: The atl2_probe function in drivers/net/ethernet/atheros/atlx/atl2.c in the Linux kernel incorrectly enabled scatter/gather I/O, which allowed remote attackers to obtain sensitive information from kernel memory by reading packet data (bnc#968697).
- CVE-2016-3070: The trace_writeback_dirty_page implementation in include/trace/events/writeback.h in the Linux kernel improperly interacted with mm/migrate.c, which allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by triggering a certain page move (bnc#979215).
- CVE-2016-5243: The tipc_nl_compat_link_dump function in net/tipc/netlink_compat.c in the Linux kernel did not properly copy a certain string, which allowed local users to obtain sensitive information from kernel stack memory by reading a Netlink message (bnc#983212).
- CVE-2016-7117: Use-after-free vulnerability in the __sys_recvmmsg function in net/socket.c in the Linux kernel allowed remote attackers to execute arbitrary code via vectors involving a recvmmsg system call that is mishandled during error processing (bnc#1003077).
- CVE-2016-9588: arch/x86/kvm/vmx.c in the Linux kernel mismanages the #BP and #OF exceptions, which allowed guest OS users to cause a denial of service (guest OS crash) by declining to handle an exception thrown by an L2 guest (bnc#1015703).
- CVE-2016-10044: The aio_mount function in fs/aio.c in the Linux kernel did not properly restrict execute access, which made it easier for local users to bypass intended SELinux W^X policy restrictions, and consequently gain privileges, via an io_setup system call (bnc#1023992).
- CVE-2016-10200: Race condition in the L2TPv3 IP Encapsulation feature in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) by making multiple bind system calls without properly ascertaining whether a socket has the SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and net/l2tp/l2tp_ip6.c (bnc#1028415).
- CVE-2016-10208: The ext4_fill_super function in fs/ext4/super.c in the Linux kernel did not properly validate meta block groups, which allowed physically proximate attackers to cause a denial of service (out-of-bounds read and system crash) via a crafted ext4 image (bnc#1023377).
- CVE-2017-2671: The ping_unhash function in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_72-default", rpm:"kgraft-patch-3_12_61-52_72-default~1~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_72-xen", rpm:"kgraft-patch-3_12_61-52_72-xen~1~2.1", rls:"SLES12.0"))) {
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
