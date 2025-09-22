# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58528");
  script_cve_id("CVE-2006-5753", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3848", "CVE-2007-3851");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1356-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1356-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1356-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1356");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1356-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1353

Ilja van Sprundel discovered that kernel memory could be leaked via the Bluetooth setsockopt call due to an uninitialized stack buffer. This could be used by local attackers to read the contents of sensitive kernel memory.

CVE-2007-2172

Thomas Graf reported a typo in the DECnet protocol handler that could be used by a local attacker to overrun an array via crafted packets, potentially resulting in a Denial of Service (system crash). A similar issue exists in the IPV4 protocol handler and will be fixed in a subsequent update.

CVE-2007-2453

A couple of issues with random number generation were discovered. Slightly less random numbers resulted from hashing a subset of the available entropy. Zero-entropy systems were seeded with the same inputs at boot time, resulting in repeatable series of random numbers.

CVE-2007-2525

Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused by releasing a socket before PPPIOCGCHAN is called upon it. This could be used by a local user to DoS a system by consuming all available memory.

CVE-2007-2876

Vilmos Nebehaj discovered a NULL pointer dereference condition in the netfilter subsystem. This allows remote systems which communicate using the SCTP protocol to crash a system by creating a connection with an unknown chunk type.

CVE-2007-3513

Oliver Neukum reported an issue in the usblcd driver which, by not limiting the size of write buffers, permits local users with write access to trigger a DoS by consuming all available memory.

CVE-2007-3642

Zhongling Wen reported an issue in nf_conntrack_h323 where the lack of range checking may lead to NULL pointer dereferences. Remote attackers could exploit this to create a DoS condition (system crash).

CVE-2007-3848

Wojciech Purczynski discovered that pdeath_signal was not being reset properly under certain conditions which may allow local users to gain privileges by sending arbitrary signals to suid binaries.

CVE-2007-3851

Dave Airlie reported that Intel 965 and above chipsets have relocated their batch buffer security bits. Local X server users may exploit this to write user data to arbitrary physical memory addresses.

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch1.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch4

user-mode-linux 2.6.18-1um-2etch3

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-alpha", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-arm", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-hppa", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-i386", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-ia64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mips", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mipsel", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-powerpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-s390", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-sparc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390-tape", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.18-5", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch1", rls:"DEB4"))) {
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
