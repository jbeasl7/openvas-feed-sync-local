# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702785");
  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928");
  script_tag(name:"creation_date", value:"2013-10-25 22:00:00 +0000 (Fri, 25 Oct 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2785-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2785-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2785");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-2906

Atte Kettunen of OUSPG discovered race conditions in Web Audio.

CVE-2013-2907

Boris Zbarsky discovered an out-of-bounds read in window.prototype.

CVE-2013-2908

Chamal de Silva discovered an address bar spoofing issue.

CVE-2013-2909

Atte Kuttenen of OUSPG discovered a use-after-free issue in inline-block.

CVE-2013-2910

Byoungyoung Lee of the Georgia Tech Information Security Center discovered a use-after-free issue in Web Audio.

CVE-2013-2911

Atte Kettunen of OUSPG discovered a use-after-free in Blink's XSLT handling.

CVE-2013-2912

Chamal de Silva and 41.w4r10r(at)garage4hackers.com discovered a use-after-free issue in the Pepper Plug-in API.

CVE-2013-2913

cloudfuzzer discovered a use-after-free issue in Blink's XML document parsing.

CVE-2013-2915

Wander Groeneveld discovered an address bar spoofing issue.

CVE-2013-2916

Masato Kinugawa discovered an address bar spoofing issue.

CVE-2013-2917

Byoungyoung Lee and Tielei Wang discovered an out-of-bounds read issue in Web Audio.

CVE-2013-2918

Byoungyoung Lee discoverd an out-of-bounds read in Blink's DOM implementation.

CVE-2013-2919

Adam Haile of Concrete Data discovered a memory corruption issue in the V8 javascript library.

CVE-2013-2920

Atte Kuttunen of OUSPG discovered an out-of-bounds read in URL host resolving.

CVE-2013-2921

Byoungyoung Lee and Tielei Wang discovered a use-after-free issue in resource loading.

CVE-2013-2922

Jon Butler discovered a use-after-free issue in Blink's HTML template element implementation.

CVE-2013-2924

A use-after-free issue was discovered in the International Components for Unicode (ICU) library.

CVE-2013-2925

Atte Kettunen of OUSPG discover a use-after-free issue in Blink's XML HTTP request implementation.

CVE-2013-2926

cloudfuzzer discovered a use-after-free issue in the list indenting implementation.

CVE-2013-2927

cloudfuzzer discovered a use-after-free issue in the HTML form submission implementation.

CVE-2013-2923 and CVE-2013-2928 The chrome 30 development team found various issues from internal fuzzing, audits, and other studies.

For the stable distribution (wheezy), these problems have been fixed in version 30.0.1599.101-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 30.0.1599.101-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"30.0.1599.101-1~deb7u1", rls:"DEB7"))) {
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
