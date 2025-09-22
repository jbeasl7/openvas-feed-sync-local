# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7691.1");
  script_cve_id("CVE-2025-50077", "CVE-2025-50078", "CVE-2025-50079", "CVE-2025-50080", "CVE-2025-50081", "CVE-2025-50082", "CVE-2025-50083", "CVE-2025-50084", "CVE-2025-50085", "CVE-2025-50086", "CVE-2025-50087", "CVE-2025-50091", "CVE-2025-50092", "CVE-2025-50093", "CVE-2025-50094", "CVE-2025-50096", "CVE-2025-50097", "CVE-2025-50098", "CVE-2025-50099", "CVE-2025-50100", "CVE-2025-50101", "CVE-2025-50102", "CVE-2025-50104", "CVE-2025-53023");
  script_tag(name:"creation_date", value:"2025-08-14 04:10:12 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:44 +0000 (Tue, 15 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7691-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7691-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7691-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-43.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-6.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2025.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0, mysql-8.4' package(s) announced via the USN-7691-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.43 in Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
Ubuntu 25.04 has been updated to MySQL 8.4.6.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[links moved to references]");

  script_tag(name:"affected", value:"'mysql-8.0, mysql-8.4' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.43-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.43-0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"8.4.6-0ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
