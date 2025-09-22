# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703351");
  script_cve_id("CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1295", "CVE-2015-1296", "CVE-2015-1297", "CVE-2015-1298", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1301");
  script_tag(name:"creation_date", value:"2015-09-02 22:00:00 +0000 (Wed, 02 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3351-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3351-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3351");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-1291

A cross-origin bypass issue was discovered in DOM.

CVE-2015-1292

Mariusz Mlynski discovered a cross-origin bypass issue in ServiceWorker.

CVE-2015-1293

Mariusz Mlynski discovered a cross-origin bypass issue in DOM.

CVE-2015-1294

cloudfuzzer discovered a use-after-free issue in the Skia graphics library.

CVE-2015-1295

A use-after-free issue was discovered in the printing component.

CVE-2015-1296

zcorpan discovered a character spoofing issue.

CVE-2015-1297

Alexander Kashev discovered a permission scoping error.

CVE-2015-1298

Rob Wu discovered an error validating the URL of extensions.

CVE-2015-1299

taro.suzuki.dev discovered a use-after-free issue in the Blink/WebKit library.

CVE-2015-1300

cgvwzq discovered an information disclosure issue in the Blink/WebKit library.

CVE-2015-1301

The chrome 45 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the libv8 library, version 4.5.103.29.

For the stable distribution (jessie), these problems have been fixed in version 45.0.2454.85-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed once the gcc-5 transition completes.

For the unstable distribution (sid), these problems have been fixed in version 45.0.2454.85-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"45.0.2454.85-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"45.0.2454.85-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"45.0.2454.85-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"45.0.2454.85-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"45.0.2454.85-1~deb8u1", rls:"DEB8"))) {
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
