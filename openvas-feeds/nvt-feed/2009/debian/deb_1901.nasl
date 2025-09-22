# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65007");
  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2009-0737");
  script_tag(name:"creation_date", value:"2009-10-06 00:49:40 +0000 (Tue, 06 Oct 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1901-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1901-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1901");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki1.7' package(s) announced via the DSA-1901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in mediawiki1.7, a website engine for collaborative work. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-5249

David Remahl discovered that mediawiki1.7 is prone to a cross-site scripting attack.

CVE-2008-5250

David Remahl discovered that mediawiki1.7, when Internet Explorer is used and uploads are enabled, or an SVG scripting browser is used and SVG uploads are enabled, allows remote authenticated users to inject arbitrary web script or HTML by editing a wiki page.

CVE-2008-5252

David Remahl discovered that mediawiki1.7 is prone to a cross-site request forgery vulnerability in the Special:Import feature.

CVE-2009-0737

It was discovered that mediawiki1.7 is prone to a cross-site scripting attack in the web-based installer.

For the oldstable distribution (etch), these problems have been fixed in version 1.7.1-9etch1 for mediawiki1.7, and mediawiki is not affected (it is a metapackage for mediawiki1.7).

The stable (lenny) distribution does not include mediawiki1.7, and these problems have been fixed in version 1:1.12.0-2lenny3 for mediawiki which was already included in the lenny release.

The unstable (sid) and testing (squeeze) distributions do not include mediawiki1.7, and these problems have been fixed in version 1:1.14.0-1 for mediawiki.

We recommend that you upgrade your mediawiki1.7 packages.");

  script_tag(name:"affected", value:"'mediawiki1.7' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki1.7", ver:"1.7.1-9etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki1.7-math", ver:"1.7.1-9etch1", rls:"DEB4"))) {
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
