# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69325");
  script_cve_id("CVE-2010-0474", "CVE-2010-1783", "CVE-2010-2901", "CVE-2010-4040", "CVE-2010-4199", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2010-11-09 00:37:00 +0000 (Tue, 09 Nov 2010)");

  script_name("Debian: Security Advisory (DSA-2188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2188-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2188-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2188");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit' package(s) announced via the DSA-2188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in WebKit, a Web content engine library for GTK+. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1783

WebKit does not properly handle dynamic modification of a text node, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

CVE-2010-2901

The rendering implementation in WebKit allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors.

CVE-2010-4199

WebKit does not properly perform a cast of an unspecified variable during processing of an SVG <use> element, which allows remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted SVG document.

CVE-2010-4040

WebKit does not properly handle animated GIF images, which allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted image.

CVE-2010-4492

Use-after-free vulnerability in WebKit allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors involving SVG animations.

CVE-2010-4493

Use-after-free vulnerability in WebKit allows remote attackers to cause a denial of service via vectors related to the handling of mouse dragging events.

CVE-2010-4577

The CSSParser::parseFontFaceSrc function in WebCore/css/CSSParser.cpp in WebKit does not properly parse Cascading Style Sheets (CSS) token sequences, which allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted local font, related to Type Confusion.

CVE-2010-4578

WebKit does not properly perform cursor handling, which allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors that lead to stale pointers.

CVE-2011-0482

WebKit does not properly perform a cast of an unspecified variable during handling of anchors, which allows remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted HTML document.

CVE-2011-0778

WebKit does not properly restrict drag and drop operations, which might allow remote attackers to bypass the Same Origin Policy via unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed in version 1.2.7-0+squeeze1.

For the testing distribution (wheezy), and the unstable distribution (sid), these problems have been fixed in version 1.2.7-1.

Security support for WebKit has been discontinued for the oldstable distribution (lenny). The current version in oldstable is not supported by upstream anymore and is affected by several security issues. Backporting fixes for these and any future issues has become unfeasible and therefore we need to drop our security support for the version in oldstable.

We recommend that you upgrade your webkit packages.");

  script_tag(name:"affected", value:"'webkit' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"gir1.0-webkit-1.0", ver:"1.2.7-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-1.0-2", ver:"1.2.7-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-1.0-2-dbg", ver:"1.2.7-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-1.0-common", ver:"1.2.7-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit-dev", ver:"1.2.7-0+squeeze1", rls:"DEB6"))) {
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
