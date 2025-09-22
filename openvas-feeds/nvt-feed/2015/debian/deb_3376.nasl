# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703376");
  script_cve_id("CVE-2015-1303", "CVE-2015-1304", "CVE-2015-6755", "CVE-2015-6756", "CVE-2015-6757", "CVE-2015-6758", "CVE-2015-6759", "CVE-2015-6760", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763");
  script_tag(name:"creation_date", value:"2015-10-19 22:00:00 +0000 (Mon, 19 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3376-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3376-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3376");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-1303

Mariusz Mlynski discovered a way to bypass the Same Origin Policy in the DOM implementation.

CVE-2015-1304

Mariusz Mlynski discovered a way to bypass the Same Origin Policy in the v8 javascript library.

CVE-2015-6755

Mariusz Mlynski discovered a way to bypass the Same Origin Policy in blink/webkit.

CVE-2015-6756

A use-after-free issue was found in the pdfium library.

CVE-2015-6757

Collin Payne found a use-after-free issue in the ServiceWorker implementation.

CVE-2015-6758

Atte Kettunen found an issue in the pdfium library.

CVE-2015-6759

Muneaki Nishimura discovered an information leak.

CVE-2015-6760

Ronald Crane discovered a logic error in the ANGLE library involving lost device events.

CVE-2015-6761

Aki Helin and Khalil Zhani discovered a memory corruption issue in the ffmpeg library.

CVE-2015-6762

Muneaki Nishimura discovered a way to bypass the Same Origin Policy in the CSS implementation.

CVE-2015-6763

The chrome 46 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the v8 javascript library, version 4.6.85.23.

For the stable distribution (jessie), these problems have been fixed in version 46.0.2490.71-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 46.0.2490.71-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"46.0.2490.71-1~deb8u1", rls:"DEB8"))) {
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
