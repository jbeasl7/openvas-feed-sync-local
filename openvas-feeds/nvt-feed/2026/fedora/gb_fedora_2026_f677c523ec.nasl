# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1026779952310199");
  script_cve_id("CVE-2025-13699");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:15 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-f677c523ec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f677c523ec");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f677c523ec");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2413295");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417695");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417697");
  script_xref(name:"URL", value:"https://mariadb.com/docs/release-notes/community-server/11.8/11.8.5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb11.8' package(s) announced via the FEDORA-2026-f677c523ec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MariaDB 11.8.5**

 Release notes: [link moved to references]");

  script_tag(name:"affected", value:"'mariadb11.8' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8", rpm:"mariadb11.8~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-backup", rpm:"mariadb11.8-backup~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-backup-debuginfo", rpm:"mariadb11.8-backup-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-client-utils", rpm:"mariadb11.8-client-utils~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-common", rpm:"mariadb11.8-common~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-connect-engine", rpm:"mariadb11.8-connect-engine~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-connect-engine-debuginfo", rpm:"mariadb11.8-connect-engine-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-cracklib-password-check", rpm:"mariadb11.8-cracklib-password-check~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-cracklib-password-check-debuginfo", rpm:"mariadb11.8-cracklib-password-check-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-debuginfo", rpm:"mariadb11.8-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-debugsource", rpm:"mariadb11.8-debugsource~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-devel", rpm:"mariadb11.8-devel~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-embedded", rpm:"mariadb11.8-embedded~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-embedded-debuginfo", rpm:"mariadb11.8-embedded-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-embedded-devel", rpm:"mariadb11.8-embedded-devel~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-errmsg", rpm:"mariadb11.8-errmsg~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-gssapi-server", rpm:"mariadb11.8-gssapi-server~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-gssapi-server-debuginfo", rpm:"mariadb11.8-gssapi-server-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-oqgraph-engine", rpm:"mariadb11.8-oqgraph-engine~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-oqgraph-engine-debuginfo", rpm:"mariadb11.8-oqgraph-engine-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-pam", rpm:"mariadb11.8-pam~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-pam-debuginfo", rpm:"mariadb11.8-pam-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-rocksdb-engine", rpm:"mariadb11.8-rocksdb-engine~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-rocksdb-engine-debuginfo", rpm:"mariadb11.8-rocksdb-engine-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-s3-engine", rpm:"mariadb11.8-s3-engine~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-s3-engine-debuginfo", rpm:"mariadb11.8-s3-engine-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-server", rpm:"mariadb11.8-server~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-server-debuginfo", rpm:"mariadb11.8-server-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-server-galera", rpm:"mariadb11.8-server-galera~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-server-galera-debuginfo", rpm:"mariadb11.8-server-galera-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-server-utils", rpm:"mariadb11.8-server-utils~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-sphinx-engine", rpm:"mariadb11.8-sphinx-engine~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-sphinx-engine-debuginfo", rpm:"mariadb11.8-sphinx-engine-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-test", rpm:"mariadb11.8-test~11.8.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb11.8-test-debuginfo", rpm:"mariadb11.8-test-debuginfo~11.8.5~1.fc42", rls:"FC42"))) {
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
