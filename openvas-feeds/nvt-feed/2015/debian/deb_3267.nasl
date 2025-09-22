# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703267");
  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1261", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265", "CVE-2015-3910");
  script_tag(name:"creation_date", value:"2015-05-21 22:00:00 +0000 (Thu, 21 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3267-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3267-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3267-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3267");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3267-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-1251

SkyLined discovered a use-after-free issue in speech recognition.

CVE-2015-1252

An out-of-bounds write issue was discovered that could be used to escape from the sandbox.

CVE-2015-1253

A cross-origin bypass issue was discovered in the DOM parser.

CVE-2015-1254

A cross-origin bypass issue was discovered in the DOM editing feature.

CVE-2015-1255

Khalil Zhani discovered a use-after-free issue in WebAudio.

CVE-2015-1256

Atte Kettunen discovered a use-after-free issue in the SVG implementation.

CVE-2015-1257

miaubiz discovered an overflow issue in the SVG implementation.

CVE-2015-1258

cloudfuzzer discovered an invalid size parameter used in the libvpx library.

CVE-2015-1259

Atte Kettunen discovered an uninitialized memory issue in the pdfium library.

CVE-2015-1260

Khalil Zhani discovered multiple use-after-free issues in chromium's interface to the WebRTC library.

CVE-2015-1261

Juho Nurminen discovered a URL bar spoofing issue.

CVE-2015-1262

miaubiz discovered the use of an uninitialized class member in font handling.

CVE-2015-1263

Mike Ruddy discovered that downloading the spellcheck dictionary was not done over HTTPS.

CVE-2015-1264

K0r3Ph1L discovered a cross-site scripting issue that could be triggered by bookmarking a site.

CVE-2015-1265

The chrome 43 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the libv8 library, version 4.3.61.21.

For the stable distribution (jessie), these problems have been fixed in version 43.0.2357.65-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 43.0.2357.65-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"43.0.2357.65-1~deb8u1", rls:"DEB8"))) {
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
