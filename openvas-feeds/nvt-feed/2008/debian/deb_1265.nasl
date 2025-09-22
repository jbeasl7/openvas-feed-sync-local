# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58120");
  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6505");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1265-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1265-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla' package(s) announced via the DSA-1265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla and derived products. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-6497

Several vulnerabilities in the layout engine allow remote attackers to cause a denial of service and possibly permit them to execute arbitrary code. [MFSA 2006-68]

CVE-2006-6498

Several vulnerabilities in the JavaScript engine allow remote attackers to cause a denial of service and possibly permit them to execute arbitrary code. [MFSA 2006-68]

CVE-2006-6499

A bug in the js_dtoa function allows remote attackers to cause a denial of service. [MFSA 2006-68]

CVE-2006-6501

shutdown discovered a vulnerability that allows remote attackers to gain privileges and install malicious code via the watch JavaScript function. [MFSA 2006-70]

CVE-2006-6502

Steven Michaud discovered a programming bug that allows remote attackers to cause a denial of service. [MFSA 2006-71]

CVE-2006-6503

moz_bug_r_a4 reported that the src attribute of an IMG element could be used to inject JavaScript code. [MFSA 2006-72]

CVE-2006-6505

Georgi Guninski discovered several heap-based buffer overflows that allow remote attackers to execute arbitrary code. [MFSA 2006-74]

For the stable distribution (sarge) these problems have been fixed in version 1.7.8-1sarge10.

For the unstable distribution (sid) these problems have been fixed in version 1.0.7-1 of iceape.

We recommend that you upgrade your Mozilla and Iceape packages.");

  script_tag(name:"affected", value:"'mozilla' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnspr-dev", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-dev", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.7.8-1sarge10", rls:"DEB3.1"))) {
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
