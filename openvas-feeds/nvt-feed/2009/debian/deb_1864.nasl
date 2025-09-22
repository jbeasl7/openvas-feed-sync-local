# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64747");
  script_cve_id("CVE-2009-2692");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1864-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1864-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1864-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1864");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6.24' package(s) announced via the DSA-1864-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the Linux kernel that may lead to privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problem:

CVE-2009-2692

Tavis Ormandy and Julien Tinnes discovered an issue with how the sendpage function is initialized in the proto_ops structure. Local users can exploit this vulnerability to gain elevated privileges.

For the oldstable distribution (etch), this problem has been fixed in version 2.6.24-6~etchnhalf.8etch3.

We recommend that you upgrade your linux-2.6.24 packages.

Note: Debian 'etch' includes linux kernel packages based upon both the 2.6.18 and 2.6.24 linux releases. All known security issues are carefully tracked against both packages and both packages will receive security updates until security support for Debian 'etch' concludes. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, lower severity 2.6.18 and 2.6.24 updates will typically release in a staggered or 'leap-frog' fashion.");

  script_tag(name:"affected", value:"'linux-2.6.24' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.24", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-alpha", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-amd64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-arm", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-hppa", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-i386", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-ia64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mips", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-s390", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-sparc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-common", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390-tape", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.24", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.24", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.24", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.24-etchnhalf.1", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.24", ver:"2.6.24-6~etchnhalf.8etch3", rls:"DEB4"))) {
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
