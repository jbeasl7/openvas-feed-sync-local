# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702799");
  script_cve_id("CVE-2013-2931", "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624", "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-6632", "CVE-2013-6802");
  script_tag(name:"creation_date", value:"2013-11-15 23:00:00 +0000 (Fri, 15 Nov 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2799-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2799-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2799-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2799");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2799-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-2931

The chrome 31 development team found various issues from internal fuzzing, audits, and other studies.

CVE-2013-6621

Khalil Zhani discovered a use-after-free issue in speech input handling.

CVE-2013-6622

cloudfuzzer discovered a use-after-free issue in HTMLMediaElement.

CVE-2013-6623

miaubiz discovered an out-of-bounds read in the Blink/Webkit SVG implementation.

CVE-2013-6624

Jon Butler discovered a use-after-free issue in id attribute strings.

CVE-2013-6625

cloudfuzzer discovered a use-after-free issue in the Blink/Webkit DOM implementation.

CVE-2013-6626

Chamal de Silva discovered an address bar spoofing issue.

CVE-2013-6627

skylined discovered an out-of-bounds read in the HTTP stream parser.

CVE-2013-6628

Antoine Delignat-Lavaud and Karthikeyan Bhargavan of INRIA Paris discovered that a different (unverified) certificate could be used after successful TLS renegotiation with a valid certificate.

CVE-2013-6629

Michal Zalewski discovered an uninitialized memory read in the libjpeg and libjpeg-turbo libraries.

CVE-2013-6630

Michal Zalewski discovered another uninitialized memory read in the libjpeg and libjpeg-turbo libraries.

CVE-2013-6631

Patrik Hoglund discovered a use-free issue in the libjingle library.

CVE-2013-6632

Pinkie Pie discovered multiple memory corruption issues.

For the stable distribution (wheezy), these problems have been fixed in version 31.0.1650.57-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 31.0.1650.57-1.

We recommend that you upgrade your chromium-browser packages.");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"31.0.1650.57-1~deb7u1", rls:"DEB7"))) {
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
