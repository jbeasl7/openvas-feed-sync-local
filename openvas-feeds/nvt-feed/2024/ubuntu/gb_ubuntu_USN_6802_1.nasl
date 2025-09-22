# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6802.1");
  script_cve_id("CVE-2024-4317");
  script_tag(name:"creation_date", value:"2024-05-30 15:06:12 +0000 (Thu, 30 May 2024)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 16:17:31 +0000 (Wed, 12 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6802-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6802-1");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/14/release-14-12.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/15/release-15-7.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/16/release-16-3.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-14, postgresql-15, postgresql-16' package(s) announced via the USN-6802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lukas Fittl discovered that PostgreSQL incorrectly performed authorization
in the built-in pg_stats_ext and pg_stats_ext_exprs views. An unprivileged
database user can use this issue to read most common values and other
statistics from CREATE STATISTICS commands of other users.

NOTE: This update will only fix fresh PostgreSQL installations. Current
PostgreSQL installations will remain vulnerable to this issue until manual
steps are performed. Please see the instructions in the changelog located
at /usr/share/doc/postgresql-*/changelog.Debian.gz after the updated
packages have been installed, or in the PostgreSQL release notes located
here:

[links moved to references]");

  script_tag(name:"affected", value:"'postgresql-14, postgresql-15, postgresql-16' package(s) on Ubuntu 22.04, Ubuntu 23.10, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-14", ver:"14.12-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-14", ver:"14.12-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-15", ver:"15.7-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-15", ver:"15.7-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-16", ver:"16.3-0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-16", ver:"16.3-0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
