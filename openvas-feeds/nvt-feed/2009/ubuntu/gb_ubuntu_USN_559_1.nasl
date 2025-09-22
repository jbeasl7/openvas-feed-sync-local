# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840106");
  script_cve_id("CVE-2007-3781", "CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6304");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-559-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-559-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0' package(s) announced via the USN-559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Gallo and Artem Russakovskii discovered that the InnoDB
engine in MySQL did not properly perform input validation. An
authenticated user could use a crafted CONTAINS statement to
cause a denial of service. (CVE-2007-5925)

It was discovered that under certain conditions MySQL could be
made to overwrite system table information. An authenticated
user could use a crafted RENAME statement to escalate privileges.
(CVE-2007-5969)

Philip Stoev discovered that the federated engine of MySQL
did not properly handle responses with a small number of columns.
An authenticated user could use a crafted response to a SHOW
TABLE STATUS query and cause a denial of service. (CVE-2007-6304)

It was discovered that MySQL did not properly enforce access
controls. An authenticated user could use a crafted CREATE TABLE
LIKE statement to escalate privileges. (CVE-2007-3781)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.24a-9ubuntu2.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.38-0ubuntu1.2", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.45-1ubuntu3.1", rls:"UBUNTU7.10"))) {
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
