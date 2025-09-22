# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840442");
  script_cve_id("CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_tag(name:"creation_date", value:"2010-06-11 11:46:51 +0000 (Fri, 11 Jun 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-950-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|6\.06\ LTS|8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-950-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-950-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) announced via the USN-950-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MySQL did not check privileges before uninstalling
plugins. An authenticated user could uninstall arbitrary plugins, bypassing
intended restrictions. This issue only affected Ubuntu 9.10 and 10.04 LTS.
(CVE-2010-1621)

It was discovered that MySQL could be made to delete another user's data
and index files. An authenticated user could use symlinks combined with the
DROP TABLE command to possibly bypass privilege checks. (CVE-2010-1626)

It was discovered that MySQL incorrectly validated the table name argument
of the COM_FIELD_LIST command. An authenticated user could use a specially-
crafted table name to bypass privilege checks and possibly access other
tables. (CVE-2010-1848)

Eric Day discovered that MySQL incorrectly handled certain network packets.
A remote attacker could exploit this flaw and cause the server to consume
all available resources, resulting in a denial of service. (CVE-2010-1849)

It was discovered that MySQL performed incorrect bounds checking on the
table name argument of the COM_FIELD_LIST command. An authenticated user
could use a specially-crafted table name to cause a denial of service or
possibly execute arbitrary code. The default compiler options for affected
releases should reduce the vulnerability to a denial of service.
(CVE-2010-1850)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0, mysql-dfsg-5.1' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.41-3ubuntu12.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.14", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-3ubuntu5.7", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.1.30really5.0.75-0ubuntu10.5", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.37-1ubuntu5.4", rls:"UBUNTU9.10"))) {
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
