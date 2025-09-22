# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1832.1");
  script_cve_id("CVE-2009-4020", "CVE-2009-4067", "CVE-2010-3880", "CVE-2010-4249", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2494", "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2928", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-4077", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4330", "CVE-2012-2136", "CVE-2012-3510", "CVE-2012-4444", "CVE-2012-4530", "CVE-2012-6537", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0268", "CVE-2013-0871", "CVE-2013-0914", "CVE-2013-1827", "CVE-2013-1928", "CVE-2013-2141", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 15:18:00 +0000 (Fri, 25 May 2012)");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1832-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131832-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:1832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 10 SP3 LTSS kernel received a roll up update to fix lots of moderate security issues and several bugs.

The Following security issues have been fixed:

 *

 CVE-2012-4530: The load_script function in fs/binfmt_script.c in the Linux kernel did not properly handle recursion, which allowed local users to obtain sensitive information from kernel stack memory via a crafted application.

 *

 CVE-2011-2494: kernel/taskstats.c in the Linux kernel allowed local users to obtain sensitive I/O statistics by sending taskstats commands to a netlink socket, as demonstrated by discovering the length of another users password.

 *

 CVE-2013-2234: The (1) key_notify_sa_flush and (2)
key_notify_policy_flush functions in net/key/af_key.c in the Linux kernel did not initialize certain structure members, which allowed local users to obtain sensitive information from kernel heap memory by reading a broadcast message from the notify interface of an IPSec key_socket.

 *

 CVE-2013-2237: The key_notify_policy_flush function in net/key/af_key.c in the Linux kernel did not initialize a certain structure member, which allowed local users to obtain sensitive information from kernel heap memory by reading a broadcast message from the notify_policy interface of an IPSec key_socket.

 *

 CVE-2013-2147: The HP Smart Array controller disk-array driver and Compaq SMART2 controller disk-array driver in the Linux kernel did not initialize certain data structures, which allowed local users to obtain sensitive information from kernel memory via (1) a crafted IDAGETPCIINFO command for a /dev/ida device, related to the ida_locked_ioctl function in drivers/block/cpqarray.c or
(2) a crafted CCISS_PASSTHRU32 command for a /dev/cciss device, related to the cciss_ioctl32_passthru function in drivers/block/cciss.c.

 *

 CVE-2013-2141: The do_tkill function in kernel/signal.c in the Linux kernel did not initialize a certain data structure, which allowed local users to obtain sensitive information from kernel memory via a crafted application that makes a (1) tkill or (2) tgkill system call.

 *

 CVE-2013-0160: The Linux kernel allowed local users to obtain sensitive information about keystroke timing by using the inotify API on the /dev/ptmx device.

 *

 CVE-2012-6537: net/xfrm/xfrm_user.c in the Linux kernel did not initialize certain structures, which allowed local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability.

 *

 CVE-2013-3222: The vcc_recvmsg function in net/atm/common.c in the Linux kernel did not initialize a certain length variable, which allowed local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

 *

 CVE-2013-3223: The ax25_recvmsg function in net/ax25/af_ax25.c in the Linux kernel did not initialize a certain data structure, which allowed local users ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.113.1", rls:"SLES10.0SP3"))) {
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
