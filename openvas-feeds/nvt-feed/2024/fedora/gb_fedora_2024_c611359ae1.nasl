# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887401");
  script_cve_id("CVE-2024-20960", "CVE-2024-20961", "CVE-2024-20962", "CVE-2024-20963", "CVE-2024-20964", "CVE-2024-20965", "CVE-2024-20966", "CVE-2024-20967", "CVE-2024-20969", "CVE-2024-20970", "CVE-2024-20971", "CVE-2024-20972", "CVE-2024-20973");
  script_tag(name:"creation_date", value:"2024-08-23 04:04:06 +0000 (Fri, 23 Aug 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:44 +0000 (Tue, 16 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c611359ae1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c611359ae1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c611359ae1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258841");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258842");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-38.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-39.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql' package(s) announced via the FEDORA-2024-c611359ae1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MySQL 8.0.39**

Release notes:

 [links moved to references]");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-common", rpm:"community-mysql-common~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-debuginfo", rpm:"community-mysql-debuginfo~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-debugsource", rpm:"community-mysql-debugsource~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-devel", rpm:"community-mysql-devel~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-devel-debuginfo", rpm:"community-mysql-devel-debuginfo~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-errmsg", rpm:"community-mysql-errmsg~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-libs", rpm:"community-mysql-libs~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-libs-debuginfo", rpm:"community-mysql-libs-debuginfo~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-server", rpm:"community-mysql-server~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-server-debuginfo", rpm:"community-mysql-server-debuginfo~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-test", rpm:"community-mysql-test~8.0.39~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"community-mysql-test-debuginfo", rpm:"community-mysql-test-debuginfo~8.0.39~1.fc39", rls:"FC39"))) {
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
