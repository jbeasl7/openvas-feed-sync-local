# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703637");
  script_cve_id("CVE-2016-1704", "CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1707", "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137");
  script_tag(name:"creation_date", value:"2016-08-04 10:57:39 +0000 (Thu, 04 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-25 16:52:30 +0000 (Mon, 25 Jul 2016)");

  script_name("Debian: Security Advisory (DSA-3637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3637-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3637-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3637");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-1704

The chrome development team found and fixed various issues during internal auditing.

CVE-2016-1705

The chrome development team found and fixed various issues during internal auditing.

CVE-2016-1706

Pinkie Pie discovered a way to escape the Pepper Plugin API sandbox.

CVE-2016-1707

xisigr discovered a URL spoofing issue.

CVE-2016-1708

Adam Varsan discovered a use-after-free issue.

CVE-2016-1709

ChenQin discovered a buffer overflow issue in the sfntly library.

CVE-2016-1710

Mariusz Mlynski discovered a same-origin bypass.

CVE-2016-1711

Mariusz Mlynski discovered another same-origin bypass.

CVE-2016-5127

cloudfuzzer discovered a use-after-free issue.

CVE-2016-5128

A same-origin bypass issue was discovered in the v8 javascript library.

CVE-2016-5129

Jeonghoon Shin discovered a memory corruption issue in the v8 javascript library.

CVE-2016-5130

Widih Matar discovered a URL spoofing issue.

CVE-2016-5131

Nick Wellnhofer discovered a use-after-free issue in the libxml2 library.

CVE-2016-5132

Ben Kelly discovered a same-origin bypass.

CVE-2016-5133

Patch Eudor discovered an issue in proxy authentication.

CVE-2016-5134

Paul Stone discovered an information leak in the Proxy Auto-Config feature.

CVE-2016-5135

ShenYeYinJiu discovered a way to bypass the Content Security Policy.

CVE-2016-5136

Rob Wu discovered a use-after-free issue.

CVE-2016-5137

Xiaoyin Liu discovered a way to discover whether an HSTS web site had been visited.

For the stable distribution (jessie), these problems have been fixed in version 52.0.2743.82-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 52.0.2743.82-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8"))) {
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
