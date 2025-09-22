# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53138");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0077");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 438-1 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20438-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9686");
  script_tag(name:"insight", value:"Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to missing function return value check
of internal functions a local attacker can gain root privileges.

For the stable distribution (woody) this problem has been fixed in
version 2.4.18-14.2 of kernel-source, version 2.4.18-14 of alpha
images, version 2.4.18-12.2 of i386 images, version 2.4.18-5woody7
of i386bf images and version 2.4.18-1woody4 of powerpc images.

Other architectures will probably mentioned in a separate advisory or
are not affected (m68k).

For the unstable distribution (sid) this problem is fixed in version
2.4.24-3 for source, i386 and alpha images and version 2.4.22-10 for
powerpc images.

This problem is also fixed in the upstream version of Linux 2.4.25 and
2.6.3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Linux kernel packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-source-2.4.18, kernel-image-2.4.18-1-alpha, kernel-image-2.4.18-1-i386, kernel-image-2.4.18-i386bf, kernel-patch-2.4.18-powerpc
announced via advisory DSA 438-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kernel-doc-2.4.18", ver:"2.4.18-14.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-source-2.4.18", ver:"2.4.18-14.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-patch-2.4.18-powerpc", ver:"2.4.18-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-generic", ver:"2.4.18-14", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-smp", ver:"2.4.18-14", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-generic", ver:"2.4.18-14", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-smp", ver:"2.4.18-14", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-386", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-586tsc", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686-smp", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k6", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k7", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-386", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-586tsc", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686-smp", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k6", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k7", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-386", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-586tsc", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686-smp", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k6", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k7", ver:"2.4.18-12.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-bf2.4", ver:"2.4.18-5woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-bf2.4", ver:"2.4.18-5woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.18", ver:"2.4.18-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-newpmac", ver:"2.4.18-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-powerpc", ver:"2.4.18-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.18-powerpc-smp", ver:"2.4.18-1woody4", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
