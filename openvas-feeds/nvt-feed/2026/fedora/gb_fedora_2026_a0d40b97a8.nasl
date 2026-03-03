# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.970100409897978");
  script_cve_id("CVE-2026-25639", "CVE-2026-27119", "CVE-2026-27121", "CVE-2026-27122", "CVE-2026-27125");
  script_tag(name:"creation_date", value:"2026-03-02 04:38:01 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-23 20:52:23 +0000 (Mon, 23 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-a0d40b97a8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-a0d40b97a8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-a0d40b97a8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439021");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439027");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441546");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441547");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441548");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441549");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441550");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441551");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441552");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441553");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4' package(s) announced via the FEDORA-2026-a0d40b97a8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Refresh vendored bundle. fixes multiple CVEs.");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-debugsource", rpm:"pgadmin4-debugsource~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-httpd", rpm:"pgadmin4-httpd~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-cs", rpm:"pgadmin4-langpack-cs~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-de", rpm:"pgadmin4-langpack-de~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-es", rpm:"pgadmin4-langpack-es~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-fr", rpm:"pgadmin4-langpack-fr~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-it", rpm:"pgadmin4-langpack-it~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ja", rpm:"pgadmin4-langpack-ja~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ko", rpm:"pgadmin4-langpack-ko~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-pl", rpm:"pgadmin4-langpack-pl~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ru", rpm:"pgadmin4-langpack-ru~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt", rpm:"pgadmin4-qt~9.12~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt-debuginfo", rpm:"pgadmin4-qt-debuginfo~9.12~2.fc43", rls:"FC43"))) {
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
