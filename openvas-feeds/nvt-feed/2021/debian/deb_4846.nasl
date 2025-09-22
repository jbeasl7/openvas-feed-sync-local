# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704846");
  script_cve_id("CVE-2020-16044", "CVE-2021-21117", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120", "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124", "CVE-2021-21125", "CVE-2021-21126", "CVE-2021-21127", "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131", "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135", "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139", "CVE-2021-21140", "CVE-2021-21141", "CVE-2021-21142", "CVE-2021-21143", "CVE-2021-21144", "CVE-2021-21145", "CVE-2021-21146", "CVE-2021-21147");
  script_tag(name:"creation_date", value:"2021-02-09 04:00:23 +0000 (Tue, 09 Feb 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-12 04:05:32 +0000 (Fri, 12 Feb 2021)");

  script_name("Debian: Security Advisory (DSA-4846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4846-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4846-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4846");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2020-16044

Ned Williamson discovered a use-after-free issue in the WebRTC implementation.

CVE-2021-21117

Rory McNamara discovered a policy enforcement issue in Cryptohome.

CVE-2021-21118

Tyler Nighswander discovered a data validation issue in the v8 javascript library.

CVE-2021-21119

A use-after-free issue was discovered in media handling.

CVE-2021-21120

Nan Wang and Guang Gong discovered a use-after-free issue in the WebSQL implementation.

CVE-2021-21121

Leecraso and Guang Gong discovered a use-after-free issue in the Omnibox.

CVE-2021-21122

Renata Hodovan discovered a use-after-free issue in Blink/WebKit.

CVE-2021-21123

Maciej Pulikowski discovered a data validation issue.

CVE-2021-21124

Chaoyang Ding discovered a use-after-free issue in the speech recognizer.

CVE-2021-21125

Ron Masas discovered a policy enforcement issue.

CVE-2021-21126

David Erceg discovered a policy enforcement issue in extensions.

CVE-2021-21127

Jasminder Pal Singh discovered a policy enforcement issue in extensions.

CVE-2021-21128

Liang Dong discovered a buffer overflow issue in Blink/WebKit.

CVE-2021-21129

Maciej Pulikowski discovered a policy enforcement issue.

CVE-2021-21130

Maciej Pulikowski discovered a policy enforcement issue.

CVE-2021-21131

Maciej Pulikowski discovered a policy enforcement issue.

CVE-2021-21132

David Erceg discovered an implementation error in the developer tools.

CVE-2021-21133

wester0x01 discovered a policy enforcement issue.

CVE-2021-21134

wester0x01 discovered a user interface error.

CVE-2021-21135

ndevtk discovered an implementation error in the Performance API.

CVE-2021-21136

Shiv Sahni, Movnavinothan V, and Imdad Mohammed discovered a policy enforcement error.

CVE-2021-21137

bobbybear discovered an implementation error in the developer tools.

CVE-2021-21138

Weipeng Jiang discovered a use-after-free issue in the developer tools.

CVE-2021-21139

Jun Kokatsu discovered an implementation error in the iframe sandbox.

CVE-2021-21140

David Manouchehri discovered uninitialized memory in the USB implementation.

CVE-2021-21141

Maciej Pulikowski discovered a policy enforcement error.

CVE-2021-21142

Khalil Zhani discovered a use-after-free issue.

CVE-2021-21143

Allen Parker and Alex Morgan discovered a buffer overflow issue in extensions.

CVE-2021-21144

Leecraso and Guang Gong discovered a buffer overflow issue.

CVE-2021-21145

A use-after-free issue was discovered.

CVE-2021-21146

Alison Huffman and Choongwoo Han discovered a use-after-free issue.

CVE-2021-21147

Roman Starkov discovered an implementation error in the skia library.

For the stable distribution (buster), these problems have been fixed in version 88.0.4324.146-1~deb10u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"88.0.4324.146-1~deb10u1", rls:"DEB10"))) {
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
