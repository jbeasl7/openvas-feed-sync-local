# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58731");
  script_cve_id("CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1399-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1399-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1399");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pcre3' package(s) announced via the DSA-1399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy of the Google Security Team has discovered several security issues in PCRE, the Perl-Compatible Regular Expression library, which potentially allow attackers to execute arbitrary code by compiling specially crafted regular expressions.

Version 7.0 of the PCRE library featured a major rewrite of the regular expression compiler, and it was deemed infeasible to backport the security fixes in version 7.3 to the versions in Debian's stable and oldstable distributions (6.7 and 4.5, respectively). Therefore, this update is based on version 7.4 (which includes the security bug fixes of the 7.3 version, plus several regression fixes), with special patches to improve the compatibility with the older versions. As a result, extra care is necessary when applying this update.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1659

Unmatched QE sequences with orphan E codes can cause the compiled regex to become desynchronized, resulting in corrupt bytecode that may result in multiple exploitable conditions.

CVE-2007-1660

Multiple forms of character classes had their sizes miscalculated on initial passes, resulting in too little memory being allocated.

CVE-2007-1661

Multiple patterns of the form X?d or P{L}?d in non-UTF-8 mode could backtrack before the start of the string, possibly leaking information from the address space, or causing a crash by reading out of bounds.

CVE-2007-1662

A number of routines can be fooled into reading past the end of a string looking for unmatched parentheses or brackets, resulting in a denial of service.

CVE-2007-4766

Multiple integer overflows in the processing of escape sequences could result in heap overflows or out of bounds reads/writes.

CVE-2007-4767

Multiple infinite loops and heap overflows were discovered in the handling of P and P{x} sequences, where the length of these non-standard operations was mishandled.

CVE-2007-4768

Character classes containing a lone unicode sequence were incorrectly optimised, resulting in a heap overflow.

For the old stable distribution (sarge), these problems have been fixed in version 4.5+7.4-1.

For the stable distribution (etch), these problems have been fixed in version 6.7+7.4-2.

For the unstable distribution (sid), these problems have been fixed in version 7.3-1.");

  script_tag(name:"affected", value:"'pcre3' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3", ver:"4.5+7.4-1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3-dev", ver:"4.5+7.4-1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcregrep", ver:"4.5+7.4-1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pgrep", ver:"4.5+7.4-1", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3", ver:"6.7+7.4-2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcre3-dev", ver:"6.7+7.4-2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpcrecpp0", ver:"6.7+7.4-2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcregrep", ver:"6.7+7.4-2", rls:"DEB4"))) {
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
