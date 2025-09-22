# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703415");
  script_cve_id("CVE-2015-1302", "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786");
  script_tag(name:"creation_date", value:"2015-12-08 23:00:00 +0000 (Tue, 08 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-07 15:12:48 +0000 (Mon, 07 Dec 2015)");

  script_name("Debian: Security Advisory (DSA-3415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3415-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3415-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3415");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-1302

Rub Wu discovered an information leak in the pdfium library.

CVE-2015-6764

Guang Gong discovered an out-of-bounds read issue in the v8 javascript library.

CVE-2015-6765

A use-after-free issue was discovered in AppCache.

CVE-2015-6766

A use-after-free issue was discovered in AppCache.

CVE-2015-6767

A use-after-free issue was discovered in AppCache.

CVE-2015-6768

Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2015-6769

Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2015-6770

Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2015-6771

An out-of-bounds read issue was discovered in the v8 javascript library.

CVE-2015-6772

Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2015-6773

cloudfuzzer discovered an out-of-bounds read issue in the skia library.

CVE-2015-6774

A use-after-free issue was found in extensions binding.

CVE-2015-6775

Atte Kettunen discovered a type confusion issue in the pdfium library.

CVE-2015-6776

Hanno Bock discovered an out-of-bounds access issue in the openjpeg library, which is used by pdfium.

CVE-2015-6777

Long Liu found a use-after-free issue.

CVE-2015-6778

Karl Skomski found an out-of-bounds read issue in the pdfium library.

CVE-2015-6779

Til Jasper Ullrich discovered that the pdfium library does not sanitize chrome: URLs.

CVE-2015-6780

Khalil Zhani discovered a use-after-free issue.

CVE-2015-6781

miaubiz discovered an integer overflow issue in the sfntly library.

CVE-2015-6782

Luan Herrera discovered a URL spoofing issue.

CVE-2015-6784

Inti De Ceukelaire discovered a way to inject HTML into serialized web pages.

CVE-2015-6785

Michael Ficarra discovered a way to bypass the Content Security Policy.

CVE-2015-6786

Michael Ficarra discovered another way to bypass the Content Security Policy.

For the stable distribution (jessie), these problems have been fixed in version 47.0.2526.73-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 47.0.2526.73-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromedriver", ver:"47.0.2526.73-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"47.0.2526.73-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"47.0.2526.73-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"47.0.2526.73-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"47.0.2526.73-1~deb8u1", rls:"DEB8"))) {
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
