# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841385");
  script_cve_id("CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");
  script_tag(name:"creation_date", value:"2013-04-05 08:21:38 +0000 (Fri, 05 Apr 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1789-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1789-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1789-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.3, postgresql-8.4, postgresql-9.1' package(s) announced via the USN-1789-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mitsumasa Kondo and Kyotaro Horiguchi discovered that PostgreSQL
incorrectly handled certain connection requests containing database names
starting with a dash. A remote attacker could use this flaw to damage or
destroy files within a server's data directory. This issue only applied to
Ubuntu 11.10, Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1899)

Marko Kreen discovered that PostgreSQL incorrectly generated random
numbers. An authenticated attacker could use this flaw to possibly guess
another database user's random numbers. (CVE-2013-1900)

Noah Misch discovered that PostgreSQL incorrectly handled certain privilege
checks. An unprivileged attacker could use this flaw to possibly interfere
with in-progress backups. This issue only applied to Ubuntu 11.10,
Ubuntu 12.04 LTS, and Ubuntu 12.10. (CVE-2013-1901)");

  script_tag(name:"affected", value:"'postgresql-8.3, postgresql-8.4, postgresql-9.1' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.17-0ubuntu10.04", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.04", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.9-0ubuntu12.10", rls:"UBUNTU12.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.23-0ubuntu8.04.1", rls:"UBUNTU8.04 LTS"))) {
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
