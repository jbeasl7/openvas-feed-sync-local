# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69968");
  script_cve_id("CVE-2011-4927", "CVE-2011-4928", "CVE-2011-4929");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2261-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2261-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2261-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2261");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'redmine' package(s) announced via the DSA-2261-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joernchen of Phenoelit discovered several vulnerabilities in Redmine, a project management web application:

Logged in users may be able to access private data.

The Textile formatter allowed for cross site scripting, exposing sensitive data to an attacker.

The Bazaar repository adapter could be used to remotely execute commands on the host running Redmine.

The oldstable distribution (lenny) does not contain redmine packages.

For the stable distribution (squeeze), this problem has been fixed in version 1.0.1-2.

For the testing distribution (wheezy) and unstable distribution (sid), this problem has been fixed in version 1.0.5-1.

We recommend that you upgrade your redmine packages.");

  script_tag(name:"affected", value:"'redmine' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"redmine", ver:"1.0.1-2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redmine-mysql", ver:"1.0.1-2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redmine-pgsql", ver:"1.0.1-2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"redmine-sqlite", ver:"1.0.1-2", rls:"DEB6"))) {
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
