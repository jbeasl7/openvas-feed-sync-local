# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703660");
  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167");
  script_tag(name:"creation_date", value:"2016-09-04 22:00:00 +0000 (Sun, 04 Sep 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-12 16:25:03 +0000 (Mon, 12 Sep 2016)");

  script_name("Debian: Security Advisory (DSA-3660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3660-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3660-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3660");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-5147

A cross-site scripting issue was discovered.

CVE-2016-5148

Another cross-site scripting issue was discovered.

CVE-2016-5149

Max Justicz discovered a script injection issue in extension handling.

CVE-2016-5150

A use-after-free issue was discovered in Blink/Webkit.

CVE-2016-5151

A use-after-free issue was discovered in the pdfium library.

CVE-2016-5152

GiWan Go discovered a heap overflow issue in the pdfium library.

CVE-2016-5153

Atte Kettunen discovered a use-after-destruction issue.

CVE-2016-5154

A heap overflow issue was discovered in the pdfium library.

CVE-2016-5155

An address bar spoofing issue was discovered.

CVE-2016-5156

jinmo123 discovered a use-after-free issue.

CVE-2016-5157

A heap overflow issue was discovered in the pdfium library.

CVE-2016-5158

GiWan Go discovered a heap overflow issue in the pdfium library.

CVE-2016-5159

GiWan Go discovered another heap overflow issue in the pdfium library.

CVE-2016-5160

@l33terally discovered an extensions resource bypass.

CVE-2016-5161

A type confusion issue was discovered.

CVE-2016-5162

Nicolas Golubovic discovered an extensions resource bypass.

CVE-2016-5163

Rafay Baloch discovered an address bar spoofing issue.

CVE-2016-5164

A cross-site scripting issue was discovered in the developer tools.

CVE-2016-5165

Gregory Panakkal discovered a script injection issue in the developer tools.

CVE-2016-5166

Gregory Panakkal discovered an issue with the Save Page As feature.

CVE-2016-5167

The chrome development team found and fixed various issues during internal auditing.

For the stable distribution (jessie), these problems have been fixed in version 53.0.2785.89-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 53.0.2785.89-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"53.0.2785.89-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"53.0.2785.89-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"53.0.2785.89-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"53.0.2785.89-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"53.0.2785.89-1~deb8u1", rls:"DEB8"))) {
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
