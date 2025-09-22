# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703590");
  script_cve_id("CVE-2016-10403", "CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670", "CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");
  script_tag(name:"creation_date", value:"2016-05-31 22:00:00 +0000 (Tue, 31 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-06 14:59:23 +0000 (Mon, 06 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3590-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3590-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3590");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3590-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-1667

Mariusz Mylinski discovered a cross-origin bypass.

CVE-2016-1668

Mariusz Mylinski discovered a cross-origin bypass in bindings to v8.

CVE-2016-1669

Choongwoo Han discovered a buffer overflow in the v8 javascript library.

CVE-2016-1670

A race condition was found that could cause the renderer process to reuse ids that should have been unique.

CVE-2016-1672

Mariusz Mylinski discovered a cross-origin bypass in extension bindings.

CVE-2016-1673

Mariusz Mylinski discovered a cross-origin bypass in Blink/Webkit.

CVE-2016-1674

Mariusz Mylinski discovered another cross-origin bypass in extension bindings.

CVE-2016-1675

Mariusz Mylinski discovered another cross-origin bypass in Blink/Webkit.

CVE-2016-1676

Rob Wu discovered a cross-origin bypass in extension bindings.

CVE-2016-1677

Guang Gong discovered a type confusion issue in the v8 javascript library.

CVE-2016-1678

Christian Holler discovered an overflow issue in the v8 javascript library.

CVE-2016-1679

Rob Wu discovered a use-after-free issue in the bindings to v8.

CVE-2016-1680

Atte Kettunen discovered a use-after-free issue in the skia library.

CVE-2016-1681

Aleksandar Nikolic discovered an overflow issue in the pdfium library.

CVE-2016-1682

KingstonTime discovered a way to bypass the Content Security Policy.

CVE-2016-1683

Nicolas Gregoire discovered an out-of-bounds write issue in the libxslt library.

CVE-2016-1684

Nicolas Gregoire discovered an integer overflow issue in the libxslt library.

CVE-2016-1685

Ke Liu discovered an out-of-bounds read issue in the pdfium library.

CVE-2016-1686

Ke Liu discovered another out-of-bounds read issue in the pdfium library.

CVE-2016-1687

Rob Wu discovered an information leak in the handling of extensions.

CVE-2016-1688

Max Korenko discovered an out-of-bounds read issue in the v8 javascript library.

CVE-2016-1689

Rob Wu discovered a buffer overflow issue.

CVE-2016-1690

Rob Wu discovered a use-after-free issue.

CVE-2016-1691

Atte Kettunen discovered a buffer overflow issue in the skia library.

CVE-2016-1692

Til Jasper Ullrich discovered a cross-origin bypass issue.

CVE-2016-1693

Khalil Zhani discovered that the Software Removal Tool download was done over an HTTP connection.

CVE-2016-1694

Ryan Lester and Bryant Zadegan discovered that pinned public keys would be removed when clearing the browser cache.

CVE-2016-1695

The chrome development team found and fixed various issues during internal auditing.

For the stable distribution (jessie), these problems have been fixed in version 51.0.2704.63-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 51.0.2704.63-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"51.0.2704.63-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"51.0.2704.63-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"51.0.2704.63-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"51.0.2704.63-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"51.0.2704.63-1~deb8u1", rls:"DEB8"))) {
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
