# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.6699101799182");
  script_cve_id("CVE-2023-52969", "CVE-2023-52970", "CVE-2023-52971");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-66ce799182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-66ce799182");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-66ce799182");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351040");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351042");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351044");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-11-11-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb10.11' package(s) announced via the FEDORA-2025-66ce799182 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**MariaDB 10.11.11**

 Release notes: [link moved to references]");

  script_tag(name:"affected", value:"'mariadb10.11' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-backup", rpm:"mariadb-backup~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-backup-debuginfo", rpm:"mariadb-backup-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-utils", rpm:"mariadb-client-utils~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-common", rpm:"mariadb-common~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect-engine", rpm:"mariadb-connect-engine~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-connect-engine-debuginfo", rpm:"mariadb-connect-engine-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-cracklib-password-check", rpm:"mariadb-cracklib-password-check~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-cracklib-password-check-debuginfo", rpm:"mariadb-cracklib-password-check-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded", rpm:"mariadb-embedded~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded-debuginfo", rpm:"mariadb-embedded-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-embedded-devel", rpm:"mariadb-embedded-devel~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errmsg", rpm:"mariadb-errmsg~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-gssapi-server", rpm:"mariadb-gssapi-server~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-gssapi-server-debuginfo", rpm:"mariadb-gssapi-server-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-oqgraph-engine", rpm:"mariadb-oqgraph-engine~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-oqgraph-engine-debuginfo", rpm:"mariadb-oqgraph-engine-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam", rpm:"mariadb-pam~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-pam-debuginfo", rpm:"mariadb-pam-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocksdb-engine", rpm:"mariadb-rocksdb-engine~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-rocksdb-engine-debuginfo", rpm:"mariadb-rocksdb-engine-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-s3-engine", rpm:"mariadb-s3-engine~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-s3-engine-debuginfo", rpm:"mariadb-s3-engine-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-debuginfo", rpm:"mariadb-server-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-galera", rpm:"mariadb-server-galera~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-utils", rpm:"mariadb-server-utils~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-server-utils-debuginfo", rpm:"mariadb-server-utils-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx-engine", rpm:"mariadb-sphinx-engine~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-sphinx-engine-debuginfo", rpm:"mariadb-sphinx-engine-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-test-debuginfo", rpm:"mariadb-test-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11", rpm:"mariadb10.11~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11-debuginfo", rpm:"mariadb10.11-debuginfo~10.11.11~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb10.11-debugsource", rpm:"mariadb10.11-debugsource~10.11.11~1.fc41", rls:"FC41"))) {
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
