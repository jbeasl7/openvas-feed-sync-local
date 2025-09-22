# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704289");
  script_cve_id("CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080", "CVE-2018-16081", "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084", "CVE-2018-16085", "CVE-2018-16086", "CVE-2018-16087", "CVE-2018-16088", "CVE-2018-16435", "CVE-2018-17457");
  script_tag(name:"creation_date", value:"2018-09-06 22:00:00 +0000 (Thu, 06 Sep 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-29 18:29:53 +0000 (Tue, 29 Jan 2019)");

  script_name("Debian: Security Advisory (DSA-4289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4289-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4289-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4289");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-4289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-16065

Brendon Tiszka discovered an out-of-bounds write issue in the v8 javascript library.

CVE-2018-16066

cloudfuzzer discovered an out-of-bounds read issue in blink/webkit.

CVE-2018-16067

Zhe Jin discovered an out-of-bounds read issue in the WebAudio implementation.

CVE-2018-16068

Mark Brand discovered an out-of-bounds write issue in the Mojo message passing library.

CVE-2018-16069

Mark Brand discovered an out-of-bounds read issue in the swiftshader library.

CVE-2018-16070

Ivan Fratric discovered an integer overflow issue in the skia library.

CVE-2018-16071

Natalie Silvanovich discovered a use-after-free issue in the WebRTC implementation.

CVE-2018-16073

Jun Kokatsu discovered an error in the Site Isolation feature when restoring browser tabs.

CVE-2018-16074

Jun Kokatsu discovered an error in the Site Isolation feature when using a Blob URL.

CVE-2018-16075

Pepe Vila discovered an error that could allow remote sites to access local files.

CVE-2018-16076

Aseksandar Nikolic discovered an out-of-bounds read issue in the pdfium library.

CVE-2018-16077

Manuel Caballero discovered a way to bypass the Content Security Policy.

CVE-2018-16078

Cailan Sacks discovered that the Autofill feature could leak saved credit card information.

CVE-2018-16079

Markus Vervier and Michele Orru discovered a URL spoofing issue.

CVE-2018-16080

Khalil Zhani discovered a URL spoofing issue.

CVE-2018-16081

Jann Horn discovered that local files could be accessed in the developer tools.

CVE-2018-16082

Omair discovered a buffer overflow issue in the swiftshader library.

CVE-2018-16083

Natalie Silvanovich discovered an out-of-bounds read issue in the WebRTC implementation.

CVE-2018-16084

Jun Kokatsu discovered a way to bypass a user confirmation dialog.

CVE-2018-16085

Roman Kuksin discovered a use-after-free issue.

For the stable distribution (stretch), these problems have been fixed in version 69.0.3497.81-1~deb9u1.

We recommend that you upgrade your chromium-browser packages.

For the detailed security status of chromium-browser please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"69.0.3497.81-1~deb9u1", rls:"DEB9"))) {
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
