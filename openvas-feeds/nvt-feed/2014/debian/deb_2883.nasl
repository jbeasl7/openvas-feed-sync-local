# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702883");
  script_cve_id("CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656", "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660", "CVE-2013-6661", "CVE-2013-6663", "CVE-2013-6664", "CVE-2013-6665", "CVE-2013-6666", "CVE-2013-6667", "CVE-2013-6668", "CVE-2014-1700", "CVE-2014-1701", "CVE-2014-1702", "CVE-2014-1703", "CVE-2014-1704", "CVE-2014-1705", "CVE-2014-1713", "CVE-2014-1715");
  script_tag(name:"creation_date", value:"2014-03-22 23:00:00 +0000 (Sat, 22 Mar 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2883-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2883-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2883");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-6653

Khalil Zhani discovered a use-after-free issue in chromium's web contents color chooser.

CVE-2013-6654

TheShow3511 discovered an issue in SVG handling.

CVE-2013-6655

cloudfuzzer discovered a use-after-free issue in dom event handling.

CVE-2013-6656

NeexEmil discovered an information leak in the XSS auditor.

CVE-2013-6657

NeexEmil discovered a way to bypass the Same Origin policy in the XSS auditor.

CVE-2013-6658

cloudfuzzer discovered multiple use-after-free issues surrounding the updateWidgetPositions function.

CVE-2013-6659

Antoine Delignat-Lavaud and Karthikeyan Bhargavan discovered that it was possible to trigger an unexpected certificate chain during TLS renegotiation.

CVE-2013-6660

bishopjeffreys discovered an information leak in the drag and drop implementation.

CVE-2013-6661

The Google Chrome team discovered and fixed multiple issues in version 33.0.1750.117.

CVE-2013-6663

Atte Kettunen discovered a use-after-free issue in SVG handling.

CVE-2013-6664

Khalil Zhani discovered a use-after-free issue in the speech recognition feature.

CVE-2013-6665

cloudfuzzer discovered a buffer overflow issue in the software renderer.

CVE-2013-6666

netfuzzer discovered a restriction bypass in the Pepper Flash plugin.

CVE-2013-6667

The Google Chrome team discovered and fixed multiple issues in version 33.0.1750.146.

CVE-2013-6668

Multiple vulnerabilities were fixed in version 3.24.35.10 of the V8 javascript library.

CVE-2014-1700

Chamal de Silva discovered a use-after-free issue in speech synthesis.

CVE-2014-1701

aidanhs discovered a cross-site scripting issue in event handling.

CVE-2014-1702

Colin Payne discovered a use-after-free issue in the web database implementation.

CVE-2014-1703

VUPEN discovered a use-after-free issue in web sockets that could lead to a sandbox escape.

CVE-2014-1704

Multiple vulnerabilities were fixed in version 3.23.17.18 of the V8 javascript library.

CVE-2014-1705

A memory corruption issue was discovered in the V8 javascript library.

CVE-2014-1713

A use-after-free issue was discovered in the AttributeSetter function.

CVE-2014-1715

A directory traversal issue was found and fixed.

For the stable distribution (wheezy), these problems have been fixed in version 33.0.1750.152-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 33.0.1750.152-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"33.0.1750.152-1~deb7u1", rls:"DEB7"))) {
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
