# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0437.1");
  script_cve_id("CVE-2004-0230", "CVE-2012-6704", "CVE-2013-6368", "CVE-2015-1350", "CVE-2015-8962", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-5696", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7916", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-8633", "CVE-2016-8646", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9685", "CVE-2016-9756", "CVE-2016-9793", "CVE-2017-5551");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:01 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 22:07:42 +0000 (Mon, 28 Nov 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0437-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170437-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/748806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/790588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/795297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999101");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002637.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to 3.0.101-94 to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2017-5551: tmpfs: clear S_ISGID when setting posix ACLs (bsc#1021258).
- CVE-2016-10088: The sg implementation in the Linux kernel did not properly restrict write operations in situations
 where the KERNEL_DS option is set, which allowed local users to read or write to arbitrary kernel memory locations
 or cause a denial of service (use-after-free) by leveraging access to a /dev/sg device
 NOTE: this vulnerability existed because of an incomplete fix for CVE-2016-9576 (bnc#1017710).
- CVE-2016-5696: TCP, when using a large Window Size, made it easier for remote attackers to guess sequence numbers
 and cause a denial of service (connection loss) to persistent TCP connections by repeatedly injecting a TCP RST
 packet, especially in protocols that use long-lived connections, such as BGP (bnc#989152).
- CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x provided an incomplete set of requirements for setattr
 operations that underspecified removing extended privilege attributes, which allowed local users to cause a denial
 of service (capability stripping) via a failed invocation of a system call, as demonstrated by using chown to remove
 a capability from the ping or Wireshark dumpcap program (bnc#914939).
- CVE-2016-8632: The tipc_msg_build function in net/tipc/msg.c in the Linux kernel did not validate the relationship
 between the minimum fragment length and the maximum packet size, which allowed local users to gain privileges or
 cause a denial of service (heap-based buffer overflow) by leveraging the CAP_NET_ADMIN capability
 (bnc#1008831).
- CVE-2016-8399: An elevation of privilege vulnerability in the kernel networking subsystem could enable a local
 malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Moderate
 because it first requires compromising a privileged process and current compiler optimizations restrict access to the
 vulnerable code. (bnc#1014746).
- CVE-2016-9793: The sock_setsockopt function in net/core/sock.c in the Linux kernel mishandled negative values of
 sk_sndbuf and sk_rcvbuf, which allowed local users to cause a denial of service (memory corruption and system crash)
 or possibly have unspecified other impact by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt system
 call with the (1) SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option (bnc#1013531).
- CVE-2012-6704: The sock_setsockopt function in net/core/sock.c in the Linux kernel mishandled negative values of
 sk_sndbuf and sk_rcvbuf, which allowed local users to cause a denial of service (memory corruption and system crash)
 or possibly have unspecified other impact by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt system
 call with the (1) SO_SNDBUF or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~94.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~94.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~94.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~94.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~94.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~94.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~94.1", rls:"SLES11.0SP4"))) {
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
