# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58340");
  script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1289-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1289-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1289");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1496

Michal Miroslaw reported a DoS vulnerability (crash) in netfilter. A remote attacker can cause a NULL pointer dereference in the nfnetlink_log function.

CVE-2007-1497

Patrick McHardy reported an vulnerability in netfilter that may allow attackers to bypass certain firewall rules. The nfctinfo value of reassembled IPv6 packet fragments were incorrectly initialized to 0 which allowed these packets to become tracked as ESTABLISHED.

CVE-2007-1861

Jaco Kroon reported a bug in which NETLINK_FIB_LOOKUP packages were incorrectly routed back to the kernel resulting in an infinite recursion condition. Local users can exploit this behavior to cause a DoS (crash).

For the stable distribution (etch) these problems have been fixed in version 2.6.18.dfsg.1-12etch2.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch2

user-mode-linux 2.6.18-1um-2etch2

kernel-patch-openvz

028.18.1etch1

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-486", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-686-bigmem", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-alpha", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-arm", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-hppa", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-i386", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-ia64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-mips", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-mipsel", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-powerpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-s390", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-all-sparc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-alpha-generic", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-alpha-legacy", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-alpha-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-footbridge", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-iop32x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-itanium", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-ixp4xx", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-k7", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-mckinley", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-parisc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-parisc-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-parisc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-parisc64-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-powerpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-powerpc-miboot", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-powerpc-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-powerpc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-prep", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-qemu", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-r3k-kn02", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-r4k-ip22", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-r4k-kn04", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-r5k-cobalt", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-r5k-ip32", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-rpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-s390", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-s390x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-s3c2410", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-sb1-bcm91250a", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-sparc32", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-sparc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-sparc64-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-alpha", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-k7", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-powerpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-powerpc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-s390x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-vserver-sparc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen-vserver", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-4-xen-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-486", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-686-bigmem", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-alpha-generic", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-alpha-legacy", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-alpha-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-footbridge", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-iop32x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-itanium", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-ixp4xx", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-k7", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-mckinley", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-parisc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-parisc-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-parisc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-parisc64-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-powerpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-powerpc-miboot", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-powerpc-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-powerpc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-prep", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-qemu", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-r3k-kn02", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-r4k-ip22", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-r4k-kn04", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-r5k-cobalt", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-r5k-ip32", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-rpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-s390", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-s390-tape", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-s390x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-s3c2410", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-sb1-bcm91250a", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-sparc32", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-sparc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-sparc64-smp", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-alpha", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-k7", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-powerpc", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-powerpc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-s390x", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-vserver-sparc64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-xen-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-xen-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-xen-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-4-xen-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-4-xen-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-4-xen-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-4-xen-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-4-xen-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.18-4", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-4-xen-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-4-xen-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-4-xen-vserver-686", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-4-xen-vserver-amd64", ver:"2.6.18.dfsg.1-12etch2", rls:"DEB4"))) {
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
