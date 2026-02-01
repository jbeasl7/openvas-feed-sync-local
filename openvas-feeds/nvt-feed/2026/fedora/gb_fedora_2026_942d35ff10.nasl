# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9421003510210210");
  script_cve_id("CVE-2025-53040", "CVE-2025-53042", "CVE-2025-53044", "CVE-2025-53045", "CVE-2025-53053", "CVE-2025-53054", "CVE-2025-53062", "CVE-2025-53069");
  script_tag(name:"creation_date", value:"2026-01-20 04:23:52 +0000 (Tue, 20 Jan 2026)");
  script_version("2026-01-20T05:50:00+0000");
  script_tag(name:"last_modification", value:"2026-01-20 05:50:00 +0000 (Tue, 20 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-21 20:20:43 +0000 (Tue, 21 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2026-942d35ff10)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-942d35ff10");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-942d35ff10");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406217");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-7.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql8.4' package(s) announced via the FEDORA-2026-942d35ff10 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MySQL 8.4.7**

 Release notes: [link moved to references]");

  script_tag(name:"affected", value:"'mysql8.4' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4", rpm:"mysql8.4~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-common", rpm:"mysql8.4-common~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-debuginfo", rpm:"mysql8.4-debuginfo~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-debugsource", rpm:"mysql8.4-debugsource~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-devel", rpm:"mysql8.4-devel~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-errmsg", rpm:"mysql8.4-errmsg~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-libs", rpm:"mysql8.4-libs~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-libs-debuginfo", rpm:"mysql8.4-libs-debuginfo~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-server", rpm:"mysql8.4-server~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-server-debuginfo", rpm:"mysql8.4-server-debuginfo~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-test", rpm:"mysql8.4-test~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-test-data", rpm:"mysql8.4-test-data~8.4.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql8.4-test-debuginfo", rpm:"mysql8.4-test-debuginfo~8.4.7~5.fc42", rls:"FC42"))) {
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
