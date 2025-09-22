# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63393");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1720-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1720-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1720-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1720");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-1720-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web content management framework.

Marcus Krause and Michael Stucki from the TYPO3 security team discovered that the jumpUrl mechanism discloses secret hashes enabling a remote attacker to bypass access control by submitting the correct value as a URL parameter and thus being able to read the content of arbitrary files.

Jelmer de Hen and Dmitry Dulepov discovered multiple cross-site scripting vulnerabilities in the backend user interface allowing remote attackers to inject arbitrary web script or HTML.

As it is very likely that your encryption key has been exposed we strongly recommend to change your encryption key via the install tool after installing the update.

For the stable distribution (etch) these problems have been fixed in version 4.0.2+debian-8.

For the testing distribution (lenny) these problems have been fixed in version 4.2.5-1+lenny1.

For the unstable distribution (sid) these problems have been fixed in version 4.2.6-1.

We recommend that you upgrade your typo3 package.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-8", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-8", rls:"DEB4"))) {
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
