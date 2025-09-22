# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0832.1");
  script_cve_id("CVE-2013-0343", "CVE-2013-2888", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4588", "CVE-2013-6382", "CVE-2013-6383", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1737", "CVE-2014-1738");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-05-12 15:10:51 +0000 (Mon, 12 May 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0832-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140832-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2014:0832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 10 SP3 LTSS received a roll up update to fix several security and non-security issues.

The following security issues have been fixed:

 *

 CVE-2013-0343: The ipv6_create_tempaddr function in net/ipv6/addrconf.c in the Linux kernel through 3.8 does not properly handle problems with the generation of IPv6 temporary addresses, which allows remote attackers to cause a denial of service (excessive retries and address-generation outage), and consequently obtain sensitive information, via ICMPv6 Router Advertisement (RA) messages. (bnc#805226)

 *

 CVE-2013-2888: Multiple array index errors in drivers/hid/hid-core.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11 allow physically proximate attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via a crafted device that provides an invalid Report ID. (bnc#835839)

 *

 CVE-2013-2893: The Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_LOGITECH_FF, CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled, allows physically proximate attackers to cause a denial of service (heap-based out-of-bounds write) via a crafted device, related to (1) drivers/hid/hid-lgff.c, (2)
drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c. (bnc#835839)

 *

 CVE-2013-2897: Multiple array index errors in drivers/hid/hid-multitouch.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_HID_MULTITOUCH is enabled,
allow physically proximate attackers to cause a denial of service (heap memory corruption, or NULL pointer dereference and OOPS) via a crafted device. (bnc#835839)

 *

 CVE-2013-4470: The Linux kernel before 3.12, when UDP Fragmentation Offload (UFO) is enabled, does not properly initialize certain data structures, which allows local users to cause a denial of service (memory corruption and system crash) or possibly gain privileges via a crafted application that uses the UDP_CORK option in a setsockopt system call and sends both short and long packets, related to the ip_ufo_append_data function in net/ipv4/ip_output.c and the ip6_ufo_append_data function in net/ipv6/ip6_output.c. (bnc#847672)

 *

 CVE-2013-4483: The ipc_rcu_putref function in ipc/util.c in the Linux kernel before 3.10 does not properly manage a reference count, which allows local users to cause a denial of service (memory consumption
 or system crash) via a crafted application. (bnc#848321)

 *

 CVE-2013-4588: Multiple stack-based buffer overflows in net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before 2.6.33, when CONFIG_IP_VS is used, allow local users to gain privileges by leveraging the CAP_NET_ADMIN capability for (1) a getsockopt system call, related to the do_ip_vs_get_ctl function, or (2) a setsockopt system call, related to the do_ip_vs_set_ctl function. (bnc#851095)

 *

 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.123.1", rls:"SLES10.0SP3"))) {
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
