# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67541");
  script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_tag(name:"creation_date", value:"2010-06-10 19:49:43 +0000 (Thu, 10 Jun 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2057-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2057-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2057");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-2057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the MySQL database server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1626

MySQL allows local users to delete the data and index files of another user's MyISAM table via a symlink attack in conjunction with the DROP TABLE command.

CVE-2010-1848

MySQL failed to check the table name argument of a COM_FIELD_LIST command packet for validity and compliance to acceptable table name standards. This allows an authenticated user with SELECT privileges on one table to obtain the field definitions of any table in all other databases and potentially of other MySQL instances accessible from the server's file system.

CVE-2010-1849

MySQL could be tricked to read packets indefinitely if it received a packet larger than the maximum size of one packet. This results in high CPU usage and thus denial of service conditions.

CVE-2010-1850

MySQL was susceptible to a buffer-overflow attack due to a failure to perform bounds checking on the table name argument of a COM_FIELD_LIST command packet. By sending long data for the table name, a buffer is overflown, which could be exploited by an authenticated user to inject malicious code.

For the stable distribution (lenny), these problems have been fixed in version 5.0.51a-24+lenny4

The testing (squeeze) and unstable (sid) distribution do not contain mysql-dfsg-5.0 anymore.

We recommend that you upgrade your mysql-dfsg-5.0 package.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-24+lenny4", rls:"DEB5"))) {
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
