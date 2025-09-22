# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6656.2");
  script_cve_id("CVE-2024-0985");
  script_tag(name:"creation_date", value:"2024-03-13 04:08:51 +0000 (Wed, 13 Mar 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 15:23:49 +0000 (Thu, 15 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6656-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6656-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6656-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.5' package(s) announced via the USN-6656-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6656-1 fixed several vulnerabilities in PostgreSQL. This update provides
the corresponding updates for Ubuntu 16.04 LTS

Original advisory details:

 It was discovered that PostgreSQL incorrectly handled dropping privileges
 when handling REFRESH MATERIALIZED VIEW CONCURRENTLY commands. If a user or
 automatic system were tricked into running a specially crafted command, a
 remote attacker could possibly use this issue to execute arbitrary SQL
 functions.");

  script_tag(name:"affected", value:"'postgresql-9.5' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.5", ver:"9.5.25-0ubuntu0.16.04.1+esm7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.5", ver:"9.5.25-0ubuntu0.16.04.1+esm7", rls:"UBUNTU16.04 LTS"))) {
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
