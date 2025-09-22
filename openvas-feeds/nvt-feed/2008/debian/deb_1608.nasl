# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61283");
  script_cve_id("CVE-2008-2079", "CVE-2008-4097");
  script_tag(name:"creation_date", value:"2008-07-15 00:29:31 +0000 (Tue, 15 Jul 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1608-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1608-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1608-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1608");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-1608-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sergei Golubchik discovered that MySQL, a widely-deployed database server, did not properly validate optional data or index directory paths given in a CREATE TABLE statement, nor would it (under proper conditions) prevent two databases from using the same paths for data or index files. This permits an authenticated user with authorization to create tables in one database to read, write or delete data from tables subsequently created in other databases, regardless of other GRANT authorizations. The Common Vulnerabilities and Exposures project identifies this weakness as CVE-2008-2079.

For the stable distribution (etch), this problem has been fixed in version 5.0.32-7etch6. Note that the fix applied will have the consequence of disallowing the selection of data or index paths under the database root, which on a Debian system is /var/lib/mysql, database administrators needing to control the placement of these files under that location must do so through other means.

We recommend that you upgrade your mysql-dfsg-5.0 packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"5.0.32-7etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.32-7etch6", rls:"DEB4"))) {
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
