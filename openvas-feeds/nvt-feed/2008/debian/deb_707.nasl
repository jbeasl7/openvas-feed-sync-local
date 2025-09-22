# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53750");
  script_cve_id("CVE-2004-0957", "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-707-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-707-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-707");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql' package(s) announced via the DSA-707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in MySQL, a popular database. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2004-0957

Sergei Golubchik discovered a problem in the access handling for similar named databases. If a user is granted privileges to a database with a name containing an underscore ('_'), the user also gains privileges to other databases with similar names.

CAN-2005-0709

Stefano Di Paola discovered that MySQL allows remote authenticated users with INSERT and DELETE privileges to execute arbitrary code by using CREATE FUNCTION to access libc calls.

CAN-2005-0710

Stefano Di Paola discovered that MySQL allows remote authenticated users with INSERT and DELETE privileges to bypass library path restrictions and execute arbitrary libraries by using INSERT INTO to modify the mysql.func table.

CAN-2005-0711

Stefano Di Paola discovered that MySQL uses predictable file names when creating temporary tables, which allows local users with CREATE TEMPORARY TABLE privileges to overwrite arbitrary files via a symlink attack.

For the stable distribution (woody) these problems have been fixed in version 3.23.49-8.11.

For the unstable distribution (sid) these problems have been fixed in version 4.0.24-5 of mysql-dfsg and in version 4.1.10a-6 of mysql-dfsg-4.1.

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.11", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.11", rls:"DEB3.0"))) {
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
