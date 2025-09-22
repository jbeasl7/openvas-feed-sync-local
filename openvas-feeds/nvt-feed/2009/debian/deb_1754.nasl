# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63796");
  script_cve_id("CVE-2009-2737");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1754-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1754-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1754-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1754");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundup' package(s) announced via the DSA-1754-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that roundup, an issue tracker with a command-line, web and email interface, allows users to edit resources in unauthorized ways, including granting themselves admin rights.

This update introduces stricter access checks, actually enforcing the configured permissions and roles. This means that the configuration may need updating. In addition, user registration via the web interface has been disabled, use the program 'roundup-admin' from the command line instead.

For the old stable distribution (etch), this problem has been fixed in version 1.2.1-10+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.4.4-4+lenny1.

We recommend that you upgrade your roundup package.");

  script_tag(name:"affected", value:"'roundup' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"roundup", ver:"1.2.1-10+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundup", ver:"1.4.4-4+lenny1", rls:"DEB5"))) {
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
