# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887407");
  script_cve_id("CVE-2024-22114", "CVE-2024-22122", "CVE-2024-22123", "CVE-2024-36460", "CVE-2024-36461");
  script_tag(name:"creation_date", value:"2024-08-24 04:04:02 +0000 (Sat, 24 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 19:21:09 +0000 (Tue, 10 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8382d1b267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8382d1b267");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8382d1b267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305135");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305143");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305147");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305155");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix' package(s) announced via the FEDORA-2024-8382d1b267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix for multiple CVEs");

  script_tag(name:"affected", value:"'zabbix' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent-debuginfo", rpm:"zabbix-agent-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-mysql", rpm:"zabbix-dbfiles-mysql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-pgsql", rpm:"zabbix-dbfiles-pgsql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-sqlite3", rpm:"zabbix-dbfiles-sqlite3~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debuginfo", rpm:"zabbix-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debugsource", rpm:"zabbix-debugsource~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql-debuginfo", rpm:"zabbix-proxy-mysql-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql", rpm:"zabbix-proxy-pgsql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql-debuginfo", rpm:"zabbix-proxy-pgsql-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite3", rpm:"zabbix-proxy-sqlite3~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite3-debuginfo", rpm:"zabbix-proxy-sqlite3-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-selinux", rpm:"zabbix-selinux~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql-debuginfo", rpm:"zabbix-server-mysql-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql", rpm:"zabbix-server-pgsql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql-debuginfo", rpm:"zabbix-server-pgsql-debuginfo~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web", rpm:"zabbix-web~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web-mysql", rpm:"zabbix-web-mysql~6.0.33~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web-pgsql", rpm:"zabbix-web-pgsql~6.0.33~1.fc40", rls:"FC40"))) {
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
