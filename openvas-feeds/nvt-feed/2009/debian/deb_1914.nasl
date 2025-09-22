# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66097");
  script_cve_id("CVE-2009-0839", "CVE-2009-0840", "CVE-2009-0841", "CVE-2009-0842", "CVE-2009-0843", "CVE-2009-1176", "CVE-2009-2281");
  script_tag(name:"creation_date", value:"2009-10-27 00:37:56 +0000 (Tue, 27 Oct 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1914-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1914-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1914");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mapserver' package(s) announced via the DSA-1914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mapserver, a CGI-based web framework to publish spatial data and interactive mapping applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0843

Missing input validation on a user supplied map queryfile name can be used by an attacker to check for the existence of a specific file by using the queryfile GET parameter and checking for differences in error messages.

CVE-2009-0842

A lack of file type verification when parsing a map file can lead to partial disclosure of content from arbitrary files through parser error messages.

CVE-2009-0841

Due to missing input validation when saving map files under certain conditions it is possible to perform directory traversal attacks and to create arbitrary files. NOTE: Unless the attacker is able to create directories in the image path or there is already a readable directory this doesn't affect installations on Linux as the fopen() syscall will fail in case a sub path is not readable.

CVE-2009-0839

It was discovered that mapserver is vulnerable to a stack-based buffer overflow when processing certain GET parameters. An attacker can use this to execute arbitrary code on the server via crafted id parameters.

CVE-2009-0840

An integer overflow leading to a heap-based buffer overflow when processing the Content-Length header of an HTTP request can be used by an attacker to execute arbitrary code via crafted POST requests containing negative Content-Length values.

CVE-2009-2281

An integer overflow when processing HTTP requests can lead to a heap-based buffer overflow. An attacker can use this to execute arbitrary code either via crafted Content-Length values or large HTTP request. This is partly because of an incomplete fix for CVE-2009-0840.

For the oldstable distribution (etch), this problem has been fixed in version 4.10.0-5.1+etch4.

For the stable distribution (lenny), this problem has been fixed in version 5.0.3-3+lenny4.

For the testing distribution (squeeze), this problem has been fixed in version 5.4.2-1.

For the unstable distribution (sid), this problem has been fixed in version 5.4.2-1.

We recommend that you upgrade your mapserver packages.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cgi-mapserver", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-bin", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-doc", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mapscript", ver:"4.10.0-5.1+etch4", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmapscript-ruby1.9", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mapscript", ver:"5.0.3-3+lenny4", rls:"DEB5"))) {
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
