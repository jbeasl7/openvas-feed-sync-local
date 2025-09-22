# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64250");
  script_cve_id("CVE-2009-1788", "CVE-2009-1791");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1814-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1814-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1814");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsndfile' package(s) announced via the DSA-1814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been found in libsndfile, a library to read and write sampled audio data. The Common Vulnerabilities and Exposures project identified the following problems:

CVE-2009-1788

Tobias Klein discovered that the VOC parsing routines suffer of a heap-based buffer overflow which can be triggered by an attacker via a crafted VOC header.

CVE-2009-1791

The vendor discovered that the AIFF parsing routines suffer of a heap-based buffer overflow similar to CVE-2009-1788 which can be triggered by an attacker via a crafted AIFF header.

In both cases the overflowing data is not completely attacker controlled but still leads to application crashes or under some circumstances might still lead to arbitrary code execution.

For the oldstable distribution (etch), this problem has been fixed in version 1.0.16-2+etch2.

For the stable distribution (lenny), this problem has been fixed in version 1.0.17-4+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.0.20-1.

We recommend that you upgrade your libsndfile packages.");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.16-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.16-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.16-2+etch2", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.17-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.17-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.17-4+lenny2", rls:"DEB5"))) {
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
