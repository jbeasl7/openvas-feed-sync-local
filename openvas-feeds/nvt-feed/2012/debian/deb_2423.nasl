# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71151");
  script_cve_id("CVE-2011-5084", "CVE-2011-5085", "CVE-2012-0317", "CVE-2012-0318", "CVE-2012-0319", "CVE-2012-0320", "CVE-2012-1262", "CVE-2012-1497");
  script_tag(name:"creation_date", value:"2012-03-12 15:33:09 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2423-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2423-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2423-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2423");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'movabletype-opensource' package(s) announced via the DSA-2423-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Movable Type, a blogging system:

Under certain circumstances, a user who has Create Entries or Manage Blog permissions may be able to read known files on the local file system.

The file management system contains shell command injection vulnerabilities, the most serious of which may lead to arbitrary OS command execution by a user who has a permission to sign-in to the admin script and also has a permission to upload files.

Session hijack and cross-site request forgery vulnerabilities exist in the commenting and the community script. A remote attacker could hijack the user session or could execute arbitrary script code on victim's browser under the certain circumstances.

Templates which do not escape variable properly and mt-wizard.cgi contain cross-site scripting vulnerabilities.

For the stable distribution (squeeze), these problems have been fixed in version 4.3.8+dfsg-0+squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 5.1.3+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages.");

  script_tag(name:"affected", value:"'movabletype-opensource' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"movabletype-opensource", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"movabletype-plugin-core", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"movabletype-plugin-zemanta", ver:"4.3.8+dfsg-0+squeeze2", rls:"DEB6"))) {
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
