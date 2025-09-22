# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844042");
  script_cve_id("CVE-2019-2614", "CVE-2019-2627");
  script_tag(name:"creation_date", value:"2019-06-06 02:00:47 +0000 (Thu, 06 Jun 2019)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 17:06:48 +0000 (Thu, 25 Apr 2019)");

  script_name("Ubuntu: Security Advisory (USN-3957-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3957-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3957-3");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-26.html");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10140-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10140-release-notes/");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-10.1' package(s) announced via the USN-3957-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3957-1 fixed multiple vulnerabilities in MySQL. This update provides the
corresponding fixes for CVE-2019-2614 and CVE-2019-2627 in MariaDB 10.1.

Ubuntu 18.04 LTS has been updated to MariaDB 10.1.40.

In addition to security fixes, the updated package contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[links moved to references]

Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 a new upstream MySQL version to fix these issues.

 Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 18.10, and Ubuntu 19.04 have
 been updated to MySQL 5.7.26.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:
 [links moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.1' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mariadb-server", ver:"1:10.1.40-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
