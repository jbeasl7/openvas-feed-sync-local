# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69970");
  script_cve_id("CVE-2010-2524", "CVE-2010-3875", "CVE-2010-4075", "CVE-2010-4655", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1017", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2182", "CVE-2011-4913");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Debian: Security Advisory (DSA-2264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2264-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2264-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2264");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2524

David Howells reported an issue in the Common Internet File System (CIFS). Local users could cause arbitrary CIFS shares to be mounted by introducing malicious redirects.

CVE-2010-3875

Vasiliy Kulikov discovered an issue in the Linux implementation of the Amateur Radio AX.25 Level 2 protocol. Local users may obtain access to sensitive kernel memory.

CVE-2010-4075

Dan Rosenberg reported an issue in the tty layer that may allow local users to obtain access to sensitive kernel memory.

CVE-2010-4655

Kees Cook discovered several issues in the ethtool interface which may allow local users with the CAP_NET_ADMIN capability to obtain access to sensitive kernel memory.

CVE-2011-0695

Jens Kuehnel reported an issue in the InfiniBand stack. Remote attackers can exploit a race condition to cause a denial of service (kernel panic).

CVE-2011-0710

Al Viro reported an issue in the /proc/<pid>/status interface on the s390 architecture. Local users could gain access to sensitive memory in processes they do not own via the task_show_regs entry.

CVE-2011-0711

Dan Rosenberg reported an issue in the XFS filesystem. Local users may obtain access to sensitive kernel memory.

CVE-2011-0726

Kees Cook reported an issue in the /proc/<pid>/stat implementation. Local users could learn the text location of a process, defeating protections provided by address space layout randomization (ASLR).

CVE-2011-1010

Timo Warns reported an issue in the Linux support for Mac partition tables. Local users with physical access could cause a denial of service (panic) by adding a storage device with a malicious map_count value.

CVE-2011-1012

Timo Warns reported an issue in the Linux support for LDM partition tables. Local users with physical access could cause a denial of service (Oops) by adding a storage device with an invalid VBLK value in the VMDB structure.

CVE-2011-1017

Timo Warns reported an issue in the Linux support for LDM partition tables. Users with physical access can gain access to sensitive kernel memory or gain elevated privileges by adding a storage device with a specially crafted LDM partition.

CVE-2011-1078

Vasiliy Kulikov discovered an issue in the Bluetooth subsystem. Local users can obtain access to sensitive kernel memory.

CVE-2011-1079

Vasiliy Kulikov discovered an issue in the Bluetooth subsystem. Local users with the CAP_NET_ADMIN capability can cause a denial of service (kernel Oops).

CVE-2011-1080

Vasiliy Kulikov discovered an issue in the Netfilter subsystem. Local users can obtain access to sensitive kernel memory.

CVE-2011-1090

Neil Horman discovered a memory leak in the setacl() call on NFSv4 filesystems. Local users ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-486", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-alpha", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-arm", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-armel", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-hppa", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-i386", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-ia64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mips", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mipsel", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-powerpc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-s390", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-sparc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-openvz", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-vserver", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-xen", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-footbridge", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-iop32x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-itanium", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-orion5x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-versatile", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-itanium", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-486", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-footbridge", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-iop32x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-itanium", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-orion5x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390-tape", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-versatile", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-itanium", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.26-2", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5"))) {
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
