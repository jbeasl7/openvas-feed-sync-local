# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0536.1");
  script_cve_id("CVE-2011-2492", "CVE-2011-2494", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6549", "CVE-2013-0343", "CVE-2013-0914", "CVE-2013-1827", "CVE-2013-2141", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2888", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-4162", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4588", "CVE-2013-6383", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-11-27 16:37:14 +0000 (Wed, 27 Nov 2013)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0536-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0536-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140536-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2014:0536-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 10 Service Pack 4 LTSS kernel has been updated to fix various security issues and several bugs.

The following security issues have been addressed:

 *

 CVE-2011-2492: The bluetooth subsystem in the Linux kernel before 3.0-rc4 does not properly initialize certain data structures, which allows local users to obtain potentially sensitive information from kernel memory via a crafted getsockopt system call, related to (1) the l2cap_sock_getsockopt_old function in net/bluetooth/l2cap_sock.c and (2) the rfcomm_sock_getsockopt_old function in net/bluetooth/rfcomm/sock.c. (bnc#702014)

 *

 CVE-2011-2494: kernel/taskstats.c in the Linux kernel before 3.1 allows local users to obtain sensitive I/O statistics by sending taskstats commands to a netlink socket, as demonstrated by discovering the length of another user's password. (bnc#703156)

 *

 CVE-2012-6537: net/xfrm/xfrm_user.c in the Linux kernel before 3.6 does not initialize certain structures,
which allows local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability. (bnc#809889)

 *

 CVE-2012-6539: The dev_ifconf function in net/socket.c in the Linux kernel before 3.6 does not initialize a certain structure, which allows local users to obtain sensitive information from kernel stack memory via a crafted application. (bnc#809891)

 *

 CVE-2012-6540: The do_ip_vs_get_ctl function in net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before 3.6 does not initialize a certain structure for IP_VS_SO_GET_TIMEOUT commands, which allows local users to obtain sensitive information from kernel stack memory via a crafted application. (bnc#809892)

 *

 CVE-2012-6541: The ccid3_hc_tx_getsockopt function in net/dccp/ccids/ccid3.c in the Linux kernel before 3.6 does not initialize a certain structure, which allows local users to obtain sensitive information from kernel stack memory via a crafted application. (bnc#809893)

 *

 CVE-2012-6542: The llc_ui_getname function in net/llc/af_llc.c in the Linux kernel before 3.6 has an incorrect return value in certain circumstances, which allows local users to obtain sensitive information from kernel stack memory via a crafted application that leverages an uninitialized pointer argument. (bnc#809894)

 *

 CVE-2012-6544: The Bluetooth protocol stack in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel stack memory via a crafted application that targets the (1) L2CAP or (2) HCI implementation. (bnc#809898)

 *

 CVE-2012-6545: The Bluetooth RFCOMM implementation in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel memory via a crafted application. (bnc#809899)

 *

 CVE-2012-6546: The ATM implementation in the Linux kernel before ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.105.1", rls:"SLES10.0SP4"))) {
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
