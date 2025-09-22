# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.7009759101277");
  script_cve_id("CVE-2024-36469", "CVE-2024-42325", "CVE-2024-45700");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-700a59e277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-700a59e277");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-700a59e277");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix' package(s) announced via the FEDORA-2025-700a59e277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 7.2.5 (CVE-2024-36469, CVE-2024-42325, CVE-2024-45700)");

  script_tag(name:"affected", value:"'zabbix' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"zabbix", rpm:"zabbix~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent-debuginfo", rpm:"zabbix-agent-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-mysql", rpm:"zabbix-dbfiles-mysql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-pgsql", rpm:"zabbix-dbfiles-pgsql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-dbfiles-sqlite3", rpm:"zabbix-dbfiles-sqlite3~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debuginfo", rpm:"zabbix-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debugsource", rpm:"zabbix-debugsource~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql-debuginfo", rpm:"zabbix-proxy-mysql-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql", rpm:"zabbix-proxy-pgsql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-pgsql-debuginfo", rpm:"zabbix-proxy-pgsql-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite3", rpm:"zabbix-proxy-sqlite3~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite3-debuginfo", rpm:"zabbix-proxy-sqlite3-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-selinux", rpm:"zabbix-selinux~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql-debuginfo", rpm:"zabbix-server-mysql-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql", rpm:"zabbix-server-pgsql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-pgsql-debuginfo", rpm:"zabbix-server-pgsql-debuginfo~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web", rpm:"zabbix-web~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web-mysql", rpm:"zabbix-web-mysql~7.2.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-web-pgsql", rpm:"zabbix-web-pgsql~7.2.5~1.fc42", rls:"FC42"))) {
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
