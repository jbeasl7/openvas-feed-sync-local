# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703731");
  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192", "CVE-2016-5193", "CVE-2016-5194", "CVE-2016-5198", "CVE-2016-5199", "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202", "CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210", "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");
  script_tag(name:"creation_date", value:"2016-12-10 23:00:00 +0000 (Sat, 10 Dec 2016)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 13:05:06 +0000 (Thu, 21 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-3731-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3731-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3731-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3731");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3731-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2016-5181

A cross-site scripting issue was discovered.

CVE-2016-5182

Giwan Go discovered a heap overflow issue.

CVE-2016-5183

A use-after-free issue was discovered in the pdfium library.

CVE-2016-5184

Another use-after-free issue was discovered in the pdfium library.

CVE-2016-5185

cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-5186

Abdulrahman Alqabandi discovered an out-of-bounds read issue in the developer tools.

CVE-2016-5187

Luan Herrera discovered a URL spoofing issue.

CVE-2016-5188

Luan Herrera discovered that some drop down menus can be used to hide parts of the user interface.

CVE-2016-5189

xisigr discovered a URL spoofing issue.

CVE-2016-5190

Atte Kettunen discovered a use-after-free issue.

CVE-2016-5191

Gareth Hughes discovered a cross-site scripting issue.

CVE-2016-5192

haojunhou@gmail.com discovered a same-origin bypass.

CVE-2016-5193

Yuyang Zhou discovered a way to pop open a new window.

CVE-2016-5194

The chrome development team found and fixed various issues during internal auditing.

CVE-2016-5198

Tencent Keen Security Lab discovered an out-of-bounds memory access issue in the v8 javascript library.

CVE-2016-5199

A heap corruption issue was discovered in the ffmpeg library.

CVE-2016-5200

Choongwoo Han discovered an out-of-bounds memory access issue in the v8 javascript library.

CVE-2016-5201

Rob Wu discovered an information leak.

CVE-2016-5202

The chrome development team found and fixed various issues during internal auditing.

CVE-2016-5203

A use-after-free issue was discovered in the pdfium library.

CVE-2016-5204

Mariusz Mlynski discovered a cross-site scripting issue in SVG image handling.

CVE-2016-5205

A cross-site scripting issue was discovered.

CVE-2016-5206

Rob Wu discovered a same-origin bypass in the pdfium library.

CVE-2016-5207

Mariusz Mlynski discovered a cross-site scripting issue.

CVE-2016-5208

Mariusz Mlynski discovered another cross-site scripting issue.

CVE-2016-5209

Giwan Go discovered an out-of-bounds write issue in Blink/Webkit.

CVE-2016-5210

Ke Liu discovered an out-of-bounds write in the pdfium library.

CVE-2016-5211

A use-after-free issue was discovered in the pdfium library.

CVE-2016-5212

Khalil Zhani discovered an information disclosure issue in the developer tools.

CVE-2016-5213

Khalil Zhani discovered a use-after-free issue in the v8 javascript library.

CVE-2016-5214

Jonathan Birch discovered a file download protection bypass.

CVE-2016-5215

Looben Yang discovered a use-after-free issue.

CVE-2016-5216

A use-after-free issue was discovered in the pdfium library.

CVE-2016-5217

Rob Wu discovered a condition where data was not validated by the pdfium library.

CVE-2016-5218

Abdulrahman Alqabandi discovered a URL spoofing issue.

CVE-2016-5219

Rob Wu discovered a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8"))) {
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
