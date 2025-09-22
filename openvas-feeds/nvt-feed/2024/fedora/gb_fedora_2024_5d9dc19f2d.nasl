# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887398");
  script_cve_id("CVE-2024-20996", "CVE-2024-21125", "CVE-2024-21127", "CVE-2024-21129", "CVE-2024-21130", "CVE-2024-21134", "CVE-2024-21142", "CVE-2024-21162", "CVE-2024-21163", "CVE-2024-21165", "CVE-2024-21171", "CVE-2024-21173", "CVE-2024-21177", "CVE-2024-21179", "CVE-2024-21185");
  script_tag(name:"creation_date", value:"2024-08-21 04:04:06 +0000 (Wed, 21 Aug 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:21 +0000 (Tue, 16 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-5d9dc19f2d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5d9dc19f2d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-5d9dc19f2d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298833");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298863");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-38.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-39.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql8.0' package(s) announced via the FEDORA-2024-5d9dc19f2d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MySQL 8.0.39**

Release notes:

 [links moved to references]");

  script_tag(name:"affected", value:"'mysql8.0' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-common", rpm:"mysql-common~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel-debuginfo", rpm:"mysql-devel-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-errmsg", rpm:"mysql-errmsg~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-libs-debuginfo", rpm:"mysql-libs-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server-debuginfo", rpm:"mysql-server-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test-debuginfo", rpm:"mysql-test-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.0", rpm:"mysql8.0~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.0-debuginfo", rpm:"mysql8.0-debuginfo~8.0.39~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.0-debugsource", rpm:"mysql8.0-debugsource~8.0.39~1.fc40", rls:"FC40"))) {
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
