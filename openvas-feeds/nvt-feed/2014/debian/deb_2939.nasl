# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702939");
  script_cve_id("CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152", "CVE-2014-3803");
  script_tag(name:"creation_date", value:"2014-05-30 22:00:00 +0000 (Fri, 30 May 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2939-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2939-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2939");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2014-1743

cloudfuzzer discovered a use-after-free issue in the Blink/Webkit document object model implementation.

CVE-2014-1744

Aaron Staple discovered an integer overflow issue in audio input handling.

CVE-2014-1745

Atte Kettunen discovered a use-after-free issue in the Blink/Webkit scalable vector graphics implementation.

CVE-2014-1746

Holger Fuhrmannek discovered an out-of-bounds read issue in the URL protocol implementation for handling media.

CVE-2014-1747

packagesu discovered a cross-site scripting issue involving malformed MHTML files.

CVE-2014-1748

Jordan Milne discovered a user interface spoofing issue.

CVE-2014-1749

The Google Chrome development team discovered and fixed multiple issues with potential security impact.

CVE-2014-3152

An integer underflow issue was discovered in the v8 javascript library.

For the stable distribution (wheezy), these problems have been fixed in version 35.0.1916.114-1~deb7u2.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 35.0.1916.114-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-dbg", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-inspector", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"35.0.1916.114-1~deb7u2", rls:"DEB7"))) {
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
