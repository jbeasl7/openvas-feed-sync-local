# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66206");
  script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3634", "CVE-2009-3635", "CVE-2009-3636");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1926-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1926-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1926-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1926");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-1926-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web content management framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3628

The Backend subcomponent allows remote authenticated users to determine an encryption key via crafted input to a form field.

CVE-2009-3629

Multiple cross-site scripting (XSS) vulnerabilities in the Backend subcomponent allow remote authenticated users to inject arbitrary web script or HTML.

CVE-2009-3630

The Backend subcomponent allows remote authenticated users to place arbitrary web sites in TYPO3 backend framesets via crafted parameters.

CVE-2009-3631

The Backend subcomponent, when the DAM extension or ftp upload is enabled, allows remote authenticated users to execute arbitrary commands via shell metacharacters in a filename.

CVE-2009-3632

SQL injection vulnerability in the traditional frontend editing feature in the Frontend Editing subcomponent allows remote authenticated users to execute arbitrary SQL commands.

CVE-2009-3633

Cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script.

CVE-2009-3634

Cross-site scripting (XSS) vulnerability in the Frontend Login Box (aka felogin) subcomponent allows remote attackers to inject arbitrary web script or HTML.

CVE-2009-3635

The Install Tool subcomponent allows remote attackers to gain access by using only the password's md5 hash as a credential.

CVE-2009-3636

Cross-site scripting (XSS) vulnerability in the Install Tool subcomponent allows remote attackers to inject arbitrary web script or HTML.

For the old stable distribution (etch), these problems have been fixed in version 4.0.2+debian-9.

For the stable distribution (lenny), these problems have been fixed in version 4.2.5-1+lenny2.

For the unstable distribution (sid), these problems have been fixed in version 4.2.10-1.

We recommend that you upgrade your typo3-src package.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-9", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-9", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny2", rls:"DEB5"))) {
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
