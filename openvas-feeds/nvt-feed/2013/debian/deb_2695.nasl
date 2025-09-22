# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702695");
  script_cve_id("CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849");
  script_tag(name:"creation_date", value:"2013-05-28 22:00:00 +0000 (Tue, 28 May 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2695-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2695-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2695");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Chromium web browser. Multiple use-after-free, out-of-bounds read, memory safety, and cross-site scripting issues were discovered and corrected.

CVE-2013-2837

Use-after-free vulnerability in the SVG implementation allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors.

CVE-2013-2838

Google V8, as used in Chromium before 27.0.1453.93, allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

CVE-2013-2839

Chromium before 27.0.1453.93 does not properly perform a cast of an unspecified variable during handling of clipboard data, which allows remote attackers to cause a denial of service or possibly have other impact via unknown vectors.

CVE-2013-2840

Use-after-free vulnerability in the media loader in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2013-2846.

CVE-2013-2841

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of Pepper resources.

CVE-2013-2842

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of widgets.

CVE-2013-2843

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the handling of speech data.

CVE-2013-2844

Use-after-free vulnerability in the Cascading Style Sheets (CSS) implementation in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to style resolution.

CVE-2013-2845

The Web Audio implementation in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via unknown vectors.

CVE-2013-2846

Use-after-free vulnerability in the media loader in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors, a different vulnerability than CVE-2013-2840.

CVE-2013-2847

Race condition in the workers implementation in Chromium before 27.0.1453.93 allows remote attackers to cause a denial of service (use-after-free and application crash) or possibly have unspecified other impact via unknown vectors.

CVE-2013-2848

The XSS Auditor in Chromium before 27.0.1453.93 might allow remote attackers to obtain sensitive information via unspecified vectors.

CVE-2013-2849

Multiple cross-site scripting (XSS) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"27.0.1453.93-1~deb7u1", rls:"DEB7"))) {
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
