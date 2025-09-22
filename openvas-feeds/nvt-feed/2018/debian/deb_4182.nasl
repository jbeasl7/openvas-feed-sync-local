# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704182");
  script_cve_id("CVE-2018-6056", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072", "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6116", "CVE-2018-6117");
  script_tag(name:"creation_date", value:"2018-04-27 22:00:00 +0000 (Fri, 27 Apr 2018)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-16 16:41:46 +0000 (Wed, 16 Jan 2019)");

  script_name("Debian: Security Advisory (DSA-4182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4182-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4182-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4182");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-4182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-6056

lokihardt discovered an error in the v8 javascript library.

CVE-2018-6057

Gal Beniamini discovered errors related to shared memory permissions.

CVE-2018-6060

Omair discovered a use-after-free issue in blink/webkit.

CVE-2018-6061

Guang Gong discovered a race condition in the v8 javascript library.

CVE-2018-6062

A heap overflow issue was discovered in the v8 javascript library.

CVE-2018-6063

Gal Beniamini discovered errors related to shared memory permissions.

CVE-2018-6064

lokihardt discovered a type confusion error in the v8 javascript library.

CVE-2018-6065

Mark Brand discovered an integer overflow issue in the v8 javascript library.

CVE-2018-6066

Masato Kinugawa discovered a way to bypass the Same Origin Policy.

CVE-2018-6067

Ned Williamson discovered a buffer overflow issue in the skia library.

CVE-2018-6068

Luan Herrera discovered object lifecycle issues.

CVE-2018-6069

Wanglu and Yangkang discovered a stack overflow issue in the skia library.

CVE-2018-6070

Rob Wu discovered a way to bypass the Content Security Policy.

CVE-2018-6071

A heap overflow issue was discovered in the skia library.

CVE-2018-6072

Atte Kettunen discovered an integer overflow issue in the pdfium library.

CVE-2018-6073

Omair discover a heap overflow issue in the WebGL implementation.

CVE-2018-6074

Abdulrahman Alqabandi discovered a way to cause a downloaded web page to not contain a Mark of the Web.

CVE-2018-6075

Inti De Ceukelaire discovered a way to bypass the Same Origin Policy.

CVE-2018-6076

Mateusz Krzeszowiec discovered that URL fragment identifiers could be handled incorrectly.

CVE-2018-6077

Khalil Zhani discovered a timing issue.

CVE-2018-6078

Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6079

Ivars discovered an information disclosure issue.

CVE-2018-6080

Gal Beniamini discovered an information disclosure issue.

CVE-2018-6081

Rob Wu discovered a cross-site scripting issue.

CVE-2018-6082

WenXu Wu discovered a way to bypass blocked ports.

CVE-2018-6083

Jun Kokatsu discovered that AppManifests could be handled incorrectly.

CVE-2018-6085

Ned Williamson discovered a use-after-free issue.

CVE-2018-6086

Ned Williamson discovered a use-after-free issue.

CVE-2018-6087

A use-after-free issue was discovered in the WebAssembly implementation.

CVE-2018-6088

A use-after-free issue was discovered in the pdfium library.

CVE-2018-6089

Rob Wu discovered a way to bypass the Same Origin Policy.

CVE-2018-6090

ZhanJia Song discovered a heap overflow issue in the skia library.

CVE-2018-6091

Jun Kokatsu discovered that plugins could be handled incorrectly.

CVE-2018-6092

Natalie Silvanovich discovered an integer overflow issue in the WebAssembly implementation.

CVE-2018-6093

Jun Kokatsu discovered a way to bypass the Same Origin ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"66.0.3359.117-1~deb9u1", rls:"DEB9"))) {
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
