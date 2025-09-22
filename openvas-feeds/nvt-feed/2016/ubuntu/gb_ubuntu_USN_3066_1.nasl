# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842865");
  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_tag(name:"creation_date", value:"2016-08-19 03:37:31 +0000 (Fri, 19 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-14 17:59:40 +0000 (Wed, 14 Dec 2016)");

  script_name("Ubuntu: Security Advisory (USN-3066-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3066-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3066-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.1, postgresql-9.3, postgresql-9.5' package(s) announced via the USN-3066-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heikki Linnakangas discovered that PostgreSQL incorrectly handled certain
nested CASE/WHEN expressions. A remote attacker could possibly use this
issue to cause PostgreSQL to crash, resulting in a denial of service.
(CVE-2016-5423)

Nathan Bossart discovered that PostgreSQL incorrectly handled special
characters in database and role names. A remote attacker could possibly use
this issue to escalate privileges. (CVE-2016-5424)");

  script_tag(name:"affected", value:"'postgresql-9.1, postgresql-9.3, postgresql-9.5' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.23-0ubuntu0.12.04", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.3", ver:"9.3.14-0ubuntu0.14.04", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.5", ver:"9.5.4-0ubuntu0.16.04", rls:"UBUNTU16.04 LTS"))) {
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
