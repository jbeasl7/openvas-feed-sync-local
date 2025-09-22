# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6968.3");
  script_cve_id("CVE-2024-7348");
  script_tag(name:"creation_date", value:"2024-10-15 04:07:59 +0000 (Tue, 15 Oct 2024)");
  script_version("2024-10-15T08:08:24+0000");
  script_tag(name:"last_modification", value:"2024-10-15 08:08:24 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 15:54:52 +0000 (Mon, 12 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-6968-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6968-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6968-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.3, postgresql-10' package(s) announced via the USN-6968-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6968-1 fixed CVE-2024-7348 in PostgreSQL-12, PostgreSQL-14, and
PostgreSQL-16.

This update provides the corresponding updates for PostgreSQL-9.3 in
Ubuntu 14.04 LTS and PostgreSQL-10 in Ubuntu 18.04 LTS.

Original advisory details:

 Noah Misch discovered that PostgreSQL incorrectly handled certain
 SQL objects. An attacker could possibly use this issue to execute
 arbitrary SQL functions as the superuser.");

  script_tag(name:"affected", value:"'postgresql-9.3, postgresql-10' package(s) on Ubuntu 14.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.3", ver:"9.3.24-0ubuntu0.14.04+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.3", ver:"9.3.24-0ubuntu0.14.04+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-10", ver:"10.23-0ubuntu0.18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-10", ver:"10.23-0ubuntu0.18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
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
