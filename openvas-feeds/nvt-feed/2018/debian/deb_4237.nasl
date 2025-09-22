# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704237");
  script_cve_id("CVE-2018-6118", "CVE-2018-6120", "CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147", "CVE-2018-6148", "CVE-2018-6149");
  script_tag(name:"creation_date", value:"2018-06-29 22:00:00 +0000 (Fri, 29 Jun 2018)");
  script_version("2024-02-01T14:37:11+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:11 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 16:02:24 +0000 (Wed, 30 Jan 2019)");

  script_name("Debian: Security Advisory (DSA-4237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4237-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4237-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4237");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium-browser");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-4237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-6118

Ned Williamson discovered a use-after-free issue.

CVE-2018-6120

Zhou Aiting discovered a buffer overflow issue in the pdfium library.

CVE-2018-6121

It was discovered that malicious extensions could escalate privileges.

CVE-2018-6122

A type confusion issue was discovered in the v8 javascript library.

CVE-2018-6123

Looben Yang discovered a use-after-free issue.

CVE-2018-6124

Guang Gong discovered a type confusion issue.

CVE-2018-6125

Yubico discovered that the WebUSB implementation was too permissive.

CVE-2018-6126

Ivan Fratric discovered a buffer overflow issue in the skia library.

CVE-2018-6127

Looben Yang discovered a use-after-free issue.

CVE-2018-6129

Natalie Silvanovich discovered an out-of-bounds read issue in WebRTC.

CVE-2018-6130

Natalie Silvanovich discovered an out-of-bounds read issue in WebRTC.

CVE-2018-6131

Natalie Silvanovich discovered an error in WebAssembly.

CVE-2018-6132

Ronald E. Crane discovered an uninitialized memory issue.

CVE-2018-6133

Khalil Zhani discovered a URL spoofing issue.

CVE-2018-6134

Jun Kokatsu discovered a way to bypass the Referrer Policy.

CVE-2018-6135

Jasper Rebane discovered a user interface spoofing issue.

CVE-2018-6136

Peter Wong discovered an out-of-bounds read issue in the v8 javascript library.

CVE-2018-6137

Michael Smith discovered an information leak.

CVE-2018-6138

Francois Lajeunesse-Robert discovered that the extensions policy was too permissive.

CVE-2018-6139

Rob Wu discovered a way to bypass restrictions in the debugger extension.

CVE-2018-6140

Rob Wu discovered a way to bypass restrictions in the debugger extension.

CVE-2018-6141

Yangkang discovered a buffer overflow issue in the skia library.

CVE-2018-6142

Choongwoo Han discovered an out-of-bounds read in the v8 javascript library.

CVE-2018-6143

Guang Gong discovered an out-of-bounds read in the v8 javascript library.

CVE-2018-6144

pdknsk discovered an out-of-bounds read in the pdfium library.

CVE-2018-6145

Masato Kinugawa discovered an error in the MathML implementation.

CVE-2018-6147

Michail Pishchagin discovered an error in password entry fields.

CVE-2018-6148

Michal Bentkowski discovered that the Content Security Policy header was handled incorrectly.

CVE-2018-6149

Yu Zhou and Jundong Xie discovered an out-of-bounds write issue in the v8 javascript library.

For the stable distribution (stretch), these problems have been fixed in version 67.0.3396.87-1~deb9u1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-widevine", ver:"67.0.3396.87-1~deb9u1", rls:"DEB9"))) {
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
