# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53666");
  script_cve_id("CVE-2003-0780");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-381");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-381");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-381");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql' package(s) announced via the DSA-381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL, a popular relational database system, contains a buffer overflow condition which could be exploited by a user who has permission to execute 'ALTER TABLE' commands on the tables in the 'mysql' database. If successfully exploited, this vulnerability could allow the attacker to execute arbitrary code with the privileges of the mysqld process (by default, user 'mysql'). Since the 'mysql' database is used for MySQL's internal record keeping, by default the mysql administrator 'root' is the only user with permission to alter its tables.

For the stable distribution (woody) this problem has been fixed in version 3.23.49-8.5.

For the unstable distribution (sid) this problem will be fixed soon. Refer to Debian bug #210403.

We recommend that you update your mysql package.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.5", rls:"DEB3.0"))) {
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
