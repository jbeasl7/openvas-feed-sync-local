# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703486");
  script_cve_id("CVE-2016-1622", "CVE-2016-1623", "CVE-2016-1624", "CVE-2016-1625", "CVE-2016-1626", "CVE-2016-1627", "CVE-2016-1628", "CVE-2016-1629");
  script_tag(name:"creation_date", value:"2016-02-20 23:00:00 +0000 (Sat, 20 Feb 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-01 14:55:59 +0000 (Tue, 01 Mar 2016)");

  script_name("Debian: Security Advisory (DSA-3486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3486-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3486-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3486");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-1622

It was discovered that a maliciously crafted extension could bypass the Same Origin Policy.

CVE-2016-1623

Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2016-1624

lukezli discovered a buffer overflow issue in the Brotli library.

CVE-2016-1625

Jann Horn discovered a way to cause the Chrome Instant feature to navigate to unintended destinations.

CVE-2016-1626

An out-of-bounds read issue was discovered in the openjpeg library.

CVE-2016-1627

It was discovered that the Developer Tools did not validate URLs.

CVE-2016-1628

An out-of-bounds read issue was discovered in the pdfium library.

CVE-2016-1629

A way to bypass the Same Origin Policy was discovered in Blink/WebKit, along with a way to escape the chromium sandbox.

For the stable distribution (jessie), these problems have been fixed in version 48.0.2564.116-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 48.0.2564.116-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"48.0.2564.116-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"48.0.2564.116-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"48.0.2564.116-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"48.0.2564.116-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"48.0.2564.116-1~deb8u1", rls:"DEB8"))) {
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
