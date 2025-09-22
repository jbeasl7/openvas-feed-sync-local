# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71475");
  script_cve_id("CVE-2012-0540", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1703", "CVE-2012-1734", "CVE-2012-2102", "CVE-2012-2122", "CVE-2012-2749");
  script_tag(name:"creation_date", value:"2012-08-10 07:06:25 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2496-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2496-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2496-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2496");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.1' package(s) announced via the DSA-2496-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to the non-disclosure of security patch information from Oracle, we are forced to ship an upstream version update of MySQL 5.1. There are several known incompatible changes, which are listed in /usr/share/doc/mysql-server/NEWS.Debian.gz.

Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to a new upstream version, 5.1.63, which includes additional changes, such as performance improvements and corrections for data loss defects. These changes are described in the MySQL release notes.

CVE-2012-2122, an authentication bypass vulnerability, occurs only when MySQL has been built in with certain optimisations enabled. The packages in Debian stable (squeeze) are not known to be affected by this vulnerability. It is addressed in this update nonetheless, so future rebuilds will not become vulnerable to this issue.

For the stable distribution (squeeze), these problems have been fixed in version 5.1.63-0+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 5.1.62-1 of the mysql-5.1 package and version 5.5.24+dfsg-1 of the mysql-5.5 package.

We recommend that you upgrade your MySQL packages.");

  script_tag(name:"affected", value:"'mysql-5.1' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.63-0+squeeze1", rls:"DEB6"))) {
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
