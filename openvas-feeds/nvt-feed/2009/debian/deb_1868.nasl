# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64749");
  script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1868-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1868-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1868-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1868");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kde4libs' package(s) announced via the DSA-1868-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in kde4libs, core libraries for all KDE 4 applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1690

It was discovered that there is a use-after-free flaw in handling certain DOM event handlers. This could lead to the execution of arbitrary code, when visiting a malicious website.

CVE-2009-1698

It was discovered that there could be an uninitialised pointer when handling a Cascading Style Sheets (CSS) attr function call. This could lead to the execution of arbitrary code, when visiting a malicious website.

CVE-2009-1687

It was discovered that the JavaScript garbage collector does not handle allocation failures properly, which could lead to the execution of arbitrary code when visiting a malicious website.

The oldstable distribution (etch) does not contain kde4libs.

For the stable distribution (lenny), these problems have been fixed in version 4:4.1.0-3+lenny1.

For the testing distribution (squeeze), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 4:4.3.0-1.

We recommend that you upgrade your kde4libs packages.");

  script_tag(name:"affected", value:"'kde4libs' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-bin", ver:"4:4.1.0-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.1.0-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-data", ver:"4:4.1.0-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-dbg", ver:"4:4.1.0-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs5-dev", ver:"4:4.1.0-3+lenny1", rls:"DEB5"))) {
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
