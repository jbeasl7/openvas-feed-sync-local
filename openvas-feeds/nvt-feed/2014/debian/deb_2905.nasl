# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702905");
  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719", "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723", "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727", "CVE-2014-1728", "CVE-2014-1729");
  script_tag(name:"creation_date", value:"2014-04-14 22:00:00 +0000 (Mon, 14 Apr 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2905-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2905-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2905");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2014-1716

A cross-site scripting issue was discovered in the v8 javascript library.

CVE-2014-1717

An out-of-bounds read issue was discovered in the v8 javascript library.

CVE-2014-1718

Aaron Staple discovered an integer overflow issue in chromium's software compositor.

CVE-2014-1719

Colin Payne discovered a use-after-free issue in the web workers implementation.

CVE-2014-1720

cloudfuzzer discovered a use-after-free issue in the Blink/Webkit document object model implementation.

CVE-2014-1721

Christian Holler discovered a memory corruption issue in the v8 javascript library.

CVE-2014-1722

miaubiz discovered a use-after-free issue in block rendering.

CVE-2014-1723

George McBay discovered a url spoofing issue.

CVE-2014-1724

Atte Kettunen discovered a use-after-free issue in freebsoft's libspeechd library.

Because of this issue, the text-to-speech feature is now disabled by default ('--enable-speech-dispatcher' at the command-line can re-enable it).

CVE-2014-1725

An out-of-bounds read was discovered in the base64 implementation.

CVE-2014-1726

Jann Horn discovered a way to bypass the same origin policy.

CVE-2014-1727

Khalil Zhani discovered a use-after-free issue in the web color chooser implementation.

CVE-2014-1728

The Google Chrome development team discovered and fixed multiple issues with potential security impact.

CVE-2014-1729

The Google Chrome development team discovered and fixed multiple issues in version 3.24.35.22 of the v8 javascript library.

For the stable distribution (wheezy), these problems have been fixed in version 34.0.1847.116-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 34.0.1847.116-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"34.0.1847.116-1~deb7u1", rls:"DEB7"))) {
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
