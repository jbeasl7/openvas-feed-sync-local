# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702818");
  script_cve_id("CVE-2013-1861", "CVE-2013-2162", "CVE-2013-3783", "CVE-2013-3793", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3809", "CVE-2013-3812", "CVE-2013-3839", "CVE-2013-5807");
  script_tag(name:"creation_date", value:"2013-12-15 23:00:00 +0000 (Sun, 15 Dec 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2818-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2818-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2818-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2818");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-32.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-33.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DSA-2818-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to a new upstream version, 5.5.33, which includes additional changes, such as performance improvements, bug fixes, new features, and possibly incompatible changes. Please see the MySQL 5.5 Release Notes for further details:

[link moved to references]

[link moved to references]

In addition this update fixes two issues affecting specifically the mysql-5.5 Debian package:

A race condition in the post-installation script of the mysql-server-5.5 package creates the configuration file /etc/mysql/debian.cnf with world-readable permissions before restricting the permissions, which allows local users to read the file and obtain sensitive information such as credentials for the debian-sys-maint to perform administration tasks. ( CVE-2013-2162)

Matthias Reichl reported that the mysql-5.5 package misses the patches applied previous in Debian's mysql-5.1 to drop the database test and the permissions that allow anonymous access, without a password, from localhost to the test database and any databases starting with test_. This update reintroduces these patches for the mysql-5.5 package.

Existing databases and permissions are not touched. Please refer to the NEWS file provided with this update for further information.

For the stable distribution (wheezy), these problems have been fixed in version 5.5.33+dfsg-0+wheezy1.

For the unstable distribution (sid), the Debian specific problems will be fixed soon.

We recommend that you upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient18", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.5", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-core-5.5", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-source-5.5", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-testsuite-5.5", ver:"5.5.33+dfsg-0+wheezy1", rls:"DEB7"))) {
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
