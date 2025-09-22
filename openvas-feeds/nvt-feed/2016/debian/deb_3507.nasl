# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703507");
  script_cve_id("CVE-2015-8126", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642", "CVE-2016-2843", "CVE-2016-2844", "CVE-2016-2845");
  script_tag(name:"creation_date", value:"2016-03-04 23:00:00 +0000 (Fri, 04 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 19:04:34 +0000 (Mon, 07 Mar 2016)");

  script_name("Debian: Security Advisory (DSA-3507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3507-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3507-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3507");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-8126

Joerg Bornemann discovered multiple buffer overflow issues in the libpng library.

CVE-2016-1630

Mariusz Mlynski discovered a way to bypass the Same Origin Policy in Blink/Webkit.

CVE-2016-1631

Mariusz Mlynski discovered a way to bypass the Same Origin Policy in the Pepper Plugin API.

CVE-2016-1632

A bad cast was discovered.

CVE-2016-1633

cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1634

cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1635

Rob Wu discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1636

A way to bypass SubResource Integrity validation was discovered.

CVE-2016-1637

Keve Nagy discovered an information leak in the skia library.

CVE-2016-1638

Rob Wu discovered a WebAPI bypass issue.

CVE-2016-1639

Khalil Zhani discovered a use-after-free issue in the WebRTC implementation.

CVE-2016-1640

Luan Herrera discovered an issue with the Extensions user interface.

CVE-2016-1641

Atte Kettunen discovered a use-after-free issue in the handling of favorite icons.

CVE-2016-1642

The chrome 49 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the v8 javascript library, version 4.9.385.26.

For the stable distribution (jessie), these problems have been fixed in version 49.0.2623.75-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 49.0.2623.75-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"49.0.2623.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"49.0.2623.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"49.0.2623.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"49.0.2623.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"49.0.2623.75-1~deb8u1", rls:"DEB8"))) {
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
