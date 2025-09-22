# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61644");
  script_cve_id("CVE-2008-3197", "CVE-2008-3456", "CVE-2008-3457", "CVE-2008-4096");
  script_tag(name:"creation_date", value:"2008-09-24 15:42:31 +0000 (Wed, 24 Sep 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1641-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1641-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1641-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1641");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-1641-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpMyAdmin, a tool to administrate MySQL databases over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4096

Remote authenticated users could execute arbitrary code on the host running phpMyAdmin through manipulation of a script parameter.

CVE-2008-3457

Cross site scripting through the setup script was possible in rare circumstances.

CVE-2008-3456

Protection has been added against remote websites loading phpMyAdmin into a frameset.

CVE-2008-3197

Cross site request forgery allowed remote attackers to create a new database, but not perform any other action on it.

For the stable distribution (etch), these problems have been fixed in version 4:2.9.1.1-8.

For the unstable distribution (sid), these problems have been fixed in version 4:2.11.8.1-2.

We recommend that you upgrade your phpmyadmin package.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:2.9.1.1-8", rls:"DEB4"))) {
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
