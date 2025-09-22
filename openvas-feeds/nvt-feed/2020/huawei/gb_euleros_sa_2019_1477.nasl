# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1477");
  script_cve_id("CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281", "CVE-2013-7339", "CVE-2013-7421", "CVE-2013-7446", "CVE-2014-0038", "CVE-2014-0049", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0100", "CVE-2014-0101", "CVE-2014-0102", "CVE-2014-0131", "CVE-2014-0155", "CVE-2014-0181");
  script_tag(name:"creation_date", value:"2020-01-23 11:50:50 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:02:39 +0000 (Mon, 28 Dec 2015)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1477)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1477");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1477");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1477 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The pn_recvmsg function in net/phonet/datagram.c in the Linux kernel before 3.12.4 updates a certain length value before ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7265)

The mISDN_sock_recvmsg function in drivers/isdn/mISDN/socket.c in the Linux kernel before 3.12.4 does not ensure that a certain length value is consistent with the size of an associated data structure, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7266)

The atalk_recvmsg function in net/appletalk/ddp.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7267)

The ipx_recvmsg function in net/ipx/af_ipx.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7268)

The nr_recvmsg function in net/netrom/af_netrom.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7269)

The packet_recvmsg function in net/packet/af_packet.c in the Linux kernel before 3.12.4 updates a certain length value before ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7270)

The x25_recvmsg function in net/x25/af_x25.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7271)

The dgram_recvmsg function in net/ieee802154/dgram.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7281)

A NULL pointer dereference flaw was found in the rds_ib_laddr_check() function in the Linux kernel's implementation of Reliable Datagram Sockets (RDS). A local, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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
