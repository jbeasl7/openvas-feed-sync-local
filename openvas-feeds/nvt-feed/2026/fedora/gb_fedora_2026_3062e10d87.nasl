# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.30621011010087");
  script_cve_id("CVE-2025-13465");
  script_tag(name:"creation_date", value:"2026-02-06 04:37:17 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-3062e10d87)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-3062e10d87");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-3062e10d87");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2432986");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433036");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4' package(s) announced via the FEDORA-2026-3062e10d87 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Regenerate vendor tarball. Fixes CVE-2025-13465.");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-debugsource", rpm:"pgadmin4-debugsource~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-httpd", rpm:"pgadmin4-httpd~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-cs", rpm:"pgadmin4-langpack-cs~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-de", rpm:"pgadmin4-langpack-de~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-es", rpm:"pgadmin4-langpack-es~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-fr", rpm:"pgadmin4-langpack-fr~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-it", rpm:"pgadmin4-langpack-it~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ja", rpm:"pgadmin4-langpack-ja~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ko", rpm:"pgadmin4-langpack-ko~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-pl", rpm:"pgadmin4-langpack-pl~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ru", rpm:"pgadmin4-langpack-ru~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt", rpm:"pgadmin4-qt~9.11~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt-debuginfo", rpm:"pgadmin4-qt-debuginfo~9.11~3.fc42", rls:"FC42"))) {
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
