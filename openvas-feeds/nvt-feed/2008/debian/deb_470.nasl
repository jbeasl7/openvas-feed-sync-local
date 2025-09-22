# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53167");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 470-1 (kernel-image-2.4.17-hppa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20470-1");
  script_tag(name:"insight", value:"Several local root exploits have been discovered recently in the Linux
kernel.  This security advisory updates the mips kernel 2.4.19 for
Debian GNU/Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:

CVE-2003-0961:

An integer overflow in brk() system call (do_brk() function) for
Linux allows a local attacker to gain root privileges.  Fixed
upstream in Linux 2.4.23.

CVE-2003-0985:

Paul Starzetz discovered a flaw in bounds checking in mremap() in
the Linux kernel (present in version 2.4.x and 2.6.x) which may
allow a local attacker to gain root privileges.  Version 2.2 is not
affected by this bug.  Fixed upstream in Linux 2.4.24.

CVE-2004-0077:

Paul Starzetz and Wojciech Purczynski of isec.pl discovered a
critical security vulnerability in the memory management code of
Linux inside the mremap(2) system call.  Due to missing function
return value check of internal functions a local attacker can gain
root privileges.  Fixed upstream in Linux 2.4.25 and 2.6.3.

For the stable distribution (woody) these problems have been fixed in
version 32.3 of kernel-image-2.4.17-hppa.

For the unstable distribution (sid) these problems have been fixed in
version 2.4.25-1 of kernel-image-2.4.25-hppa.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Linux kernel packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-image-2.4.17-hppa
announced via advisory DSA 470-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kernel-source-2.4.17-hppa", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-hppa", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32-smp", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64-smp", ver:"32.3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
