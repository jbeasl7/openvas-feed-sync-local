# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887220");
  script_cve_id("CVE-2024-21096");
  script_tag(name:"creation_date", value:"2024-06-10 04:08:19 +0000 (Mon, 10 Jun 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:30 +0000 (Tue, 16 Apr 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-6ea93e629b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6ea93e629b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6ea93e629b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2256983");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282490");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283500");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-11-7-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-11-8-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'galera, mariadb10.11' package(s) announced via the FEDORA-2024-6ea93e629b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MariaDB 10.11.8 & Galera 26.4.18**

Release notes:

 [links moved to references]");

  script_tag(name:"affected", value:"'galera, mariadb10.11' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"galera", rpm:"galera~26.4.18~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"galera-debuginfo", rpm:"galera-debuginfo~26.4.18~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"galera-debugsource", rpm:"galera-debugsource~26.4.18~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-backup", rpm:"mariadb-backup~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-backup-debuginfo", rpm:"mariadb-backup-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect-engine", rpm:"mariadb-connect-engine~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect-engine-debuginfo", rpm:"mariadb-connect-engine-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-cracklib-password-check", rpm:"mariadb-cracklib-password-check~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-cracklib-password-check-debuginfo", rpm:"mariadb-cracklib-password-check-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded", rpm:"mariadb-embedded~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded-debuginfo", rpm:"mariadb-embedded-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded-devel", rpm:"mariadb-embedded-devel~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errmsg", rpm:"mariadb-errmsg~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-gssapi-server", rpm:"mariadb-gssapi-server~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-gssapi-server-debuginfo", rpm:"mariadb-gssapi-server-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-oqgraph-engine", rpm:"mariadb-oqgraph-engine~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-oqgraph-engine-debuginfo", rpm:"mariadb-oqgraph-engine-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam", rpm:"mariadb-pam~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam-debuginfo", rpm:"mariadb-pam-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocksdb-engine", rpm:"mariadb-rocksdb-engine~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocksdb-engine-debuginfo", rpm:"mariadb-rocksdb-engine-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-s3-engine", rpm:"mariadb-s3-engine~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-s3-engine-debuginfo", rpm:"mariadb-s3-engine-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-debuginfo", rpm:"mariadb-server-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-galera", rpm:"mariadb-server-galera~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-utils", rpm:"mariadb-server-utils~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-utils-debuginfo", rpm:"mariadb-server-utils-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx-engine", rpm:"mariadb-sphinx-engine~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx-engine-debuginfo", rpm:"mariadb-sphinx-engine-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11", rpm:"mariadb10.11~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11-debuginfo", rpm:"mariadb10.11-debuginfo~10.11.8~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11-debugsource", rpm:"mariadb10.11-debugsource~10.11.8~1.fc40", rls:"FC40"))) {
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
