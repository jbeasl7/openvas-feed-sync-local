# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703555");
  script_cve_id("CVE-2011-5326", "CVE-2014-9771", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024");
  script_tag(name:"creation_date", value:"2016-04-22 22:00:00 +0000 (Fri, 22 Apr 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-13 18:18:53 +0000 (Fri, 13 May 2016)");

  script_name("Debian: Security Advisory (DSA-3555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3555-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3555-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3555");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imlib2' package(s) announced via the DSA-3555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in imlib2, an image manipulation library.

CVE-2011-5326

Kevin Ryde discovered that attempting to draw a 2x1 radi ellipse results in a floating point exception.

CVE-2014-9771

It was discovered that an integer overflow could lead to invalid memory reads and unreasonably large memory allocations.

CVE-2016-3993

Yuriy M. Kaminskiy discovered that drawing using coordinates from an untrusted source could lead to an out-of-bound memory read, which in turn could result in an application crash.

CVE-2016-3994

Jakub Wilk discovered that a malformed image could lead to an out-of-bound read in the GIF loader, which may result in an application crash or information leak.

CVE-2016-4024

Yuriy M. Kaminskiy discovered an integer overflow that could lead to an insufficient heap allocation and out-of-bound memory write.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.4.5-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 1.4.6-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 1.4.8-1.

We recommend that you upgrade your imlib2 packages.");

  script_tag(name:"affected", value:"'imlib2' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libimlib2", ver:"1.4.5-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimlib2-dev", ver:"1.4.5-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libimlib2", ver:"1.4.6-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimlib2-dev", ver:"1.4.6-2+deb8u2", rls:"DEB8"))) {
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
