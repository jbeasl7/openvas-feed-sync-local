# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2525.1");
  script_cve_id("CVE-2016-10200", "CVE-2016-5243", "CVE-2017-1000112", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11176", "CVE-2017-11473", "CVE-2017-12762", "CVE-2017-14051", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-6951", "CVE-2017-7184", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7482", "CVE-2017-7487", "CVE-2017-7533", "CVE-2017-7542", "CVE-2017-7616", "CVE-2017-8831", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 14:55:05 +0000 (Fri, 25 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2525-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172525-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999245");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2016-5243: The tipc_nl_compat_link_dump function in net/tipc/netlink_compat.c in the Linux kernel did not properly copy a certain string, which allowed local users to obtain sensitive information from kernel stack memory by reading a Netlink message (bnc#983212)
- CVE-2016-10200: Race condition in the L2TPv3 IP Encapsulation feature in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) by making multiple bind system calls without properly ascertaining whether a socket has the SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and net/l2tp/l2tp_ip6.c (bnc#1028415)
- CVE-2017-2647: The KEYS subsystem in the Linux kernel allowed local users to gain privileges or cause a denial of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain match field, related to the keyring_search_iterator function in keyring.c (bsc#1030593).
- CVE-2017-2671: The ping_unhash function in net/ipv4/ping.c in the Linux kernel was too late in obtaining a certain lock and consequently could not ensure that disconnect function calls are safe, which allowed local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call (bnc#1031003)
- CVE-2017-5669: The do_shmat function in ipc/shm.c in the Linux kernel did not restrict the address calculated by a certain rounding operation, which allowed local users to map page zero, and consequently bypass a protection mechanism that exists for the mmap system call, by making crafted shmget and shmat system calls in a privileged context (bnc#1026914)
- CVE-2017-5970: The ipv4_pktinfo_prepare function in net/ipv4/ip_sockglue.c in the Linux kernel allowed attackers to cause a denial of service (system crash) via (1) an application that made crafted system calls or possibly (2) IPv4 traffic with invalid IP options (bsc#1024938)
- CVE-2017-5986: Race condition in the sctp_wait_for_sndbuf function in net/sctp/socket.c in the Linux kernel allowed local users to cause a denial of service (assertion failure and panic) via a multithreaded application that peels off an association in a certain buffer-full state (bsc#1025235)
- CVE-2017-6074: The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel mishandled DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allowed local users to obtain root privileges or cause a denial of service (double free) via an application that made an IPV6_RECVPKTINFO setsockopt system call (bnc#1026024)
- CVE-2017-6214: The tcp_splice_read function in net/ipv4/tcp.c in the Linux kernel allowed remote attackers to cause a denial of service (infinite loop and soft lockup) via vectors involving a TCP packet with the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.106.5.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.106.5.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.106.5.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.106.5.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.106.5.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.106.5.1", rls:"SLES11.0SP3"))) {
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
