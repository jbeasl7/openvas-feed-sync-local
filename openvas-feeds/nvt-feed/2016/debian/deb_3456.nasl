# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703456");
  script_cve_id("CVE-2015-6792", "CVE-2016-1612", "CVE-2016-1613", "CVE-2016-1614", "CVE-2016-1615", "CVE-2016-1616", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1619", "CVE-2016-1620");
  script_tag(name:"creation_date", value:"2016-01-26 23:00:00 +0000 (Tue, 26 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-24 17:37:07 +0000 (Thu, 24 Dec 2015)");

  script_name("Debian: Security Advisory (DSA-3456-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3456-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3456-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3456");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3456-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-6792

An issue was found in the handling of MIDI files.

CVE-2016-1612

cloudfuzzer discovered a logic error related to receiver compatibility in the v8 javascript library.

CVE-2016-1613

A use-after-free issue was discovered in the pdfium library.

CVE-2016-1614

Christoph Diehl discovered an information leak in Webkit/Blink.

CVE-2016-1615

Ron Masas discovered a way to spoof URLs.

CVE-2016-1616

Luan Herrera discovered a way to spoof URLs.

CVE-2016-1617

jenuis discovered a way to discover whether an HSTS web site had been visited.

CVE-2016-1618

Aaron Toponce discovered the use of weak random number generator.

CVE-2016-1619

Keve Nagy discovered an out-of-bounds-read issue in the pdfium library.

CVE-2016-1620

The chrome 48 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the v8 javascript library, version 4.7.271.17.

For the stable distribution (jessie), these problems have been fixed in version 48.0.2564.82-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 48.0.2564.82-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"48.0.2564.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"48.0.2564.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"48.0.2564.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"48.0.2564.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"48.0.2564.82-1~deb8u1", rls:"DEB8"))) {
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
