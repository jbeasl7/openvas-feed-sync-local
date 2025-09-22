# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58667");
  script_cve_id("CVE-2006-5755", "CVE-2007-4133", "CVE-2007-4573", "CVE-2007-5093");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1381-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1381-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1381-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1381");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1381-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-5755

The NT bit maybe leaked into the next task which can make it possible for local attackers to cause a Denial of Service (crash) on systems which run the amd64 flavour kernel. The stable distribution (etch) was not believed to be vulnerable to this issue at the time of release, however Bastian Blank discovered that this issue still applied to the xen-amd64 and xen-vserver-amd64 flavours, and is resolved by this DSA.

CVE-2007-4133

Hugh Dickins discovered a potential local DoS (panic) in hugetlbfs. A misconversion of hugetlb_vmtruncate_list to prio_tree may allow local users to trigger a BUG_ON() call in exit_mmap.

CVE-2007-4573

Wojciech Purczynski discovered a vulnerability that can be exploited by a local user to obtain superuser privileges on x86_64 systems. This resulted from improper clearing of the high bits of registers during ia32 system call emulation. This vulnerability is relevant to the Debian amd64 port as well as users of the i386 port who run the amd64 linux-image flavour.

DSA-1378 resolved this problem for the amd64 flavour kernels, but Tim Wickberg and Ralf Hemmenstadt reported an outstanding issue with the xen-amd64 and xen-vserver-amd64 flavours that is resolved by this DSA.

CVE-2007-5093

Alex Smith discovered an issue with the pwc driver for certain webcam devices. If the device is removed while a userspace application has it open, the driver will wait for userspace to close the device, resulting in a blocked USB subsystem. This issue is of low security impact as it requires the attacker to either have physical access to the system or to convince users with local access to remove the device on their behalf.

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch4.

This is an update to DSA-1381-1 which included only amd64 binaries for linux-2.6. Builds for all other architectures are now available, as well as rebuilds of ancillary packages that make use of the included linux source.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch.13etch4

kernel-patch-openvz 028.18.1etch5

user-mode-linux 2.6.18-1um-2etch.13etch4

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-alpha", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-arm", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-hppa", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-i386", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-ia64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mips", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mipsel", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-powerpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-s390", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-sparc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390-tape", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.18-5", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch4", rls:"DEB4"))) {
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
