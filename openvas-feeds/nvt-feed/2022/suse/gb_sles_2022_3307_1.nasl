# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3307.1");
  script_cve_id("CVE-2021-36690", "CVE-2022-35737");
  script_tag(name:"creation_date", value:"2022-09-20 04:49:26 +0000 (Tue, 20 Sep 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-10 15:07:23 +0000 (Wed, 10 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3307-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223307-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3' package(s) announced via the SUSE-SU-2022:3307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sqlite3 fixes the following issues:

CVE-2022-35737: Fixed an array-bounds overflow if billions of bytes are
 used in a string argument to a C API (bnc#1201783).

CVE-2021-36690: Fixed an issue with the SQLite Expert extension when a
 column has no collating sequence (bsc#1189802).

Package the Tcl bindings here again so that we only ship one copy of
 SQLite (bsc#1195773).");

  script_tag(name:"affected", value:"'sqlite3' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0", rpm:"libsqlite3-0~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit", rpm:"libsqlite3-0-32bit~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit-debuginfo", rpm:"libsqlite3-0-32bit-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-debuginfo", rpm:"libsqlite3-0-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debuginfo", rpm:"sqlite3-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debugsource", rpm:"sqlite3-debugsource~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-devel", rpm:"sqlite3-devel~3.39.3~150000.3.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0", rpm:"libsqlite3-0~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit", rpm:"libsqlite3-0-32bit~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-32bit-debuginfo", rpm:"libsqlite3-0-32bit-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-0-debuginfo", rpm:"libsqlite3-0-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debuginfo", rpm:"sqlite3-debuginfo~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-debugsource", rpm:"sqlite3-debugsource~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-devel", rpm:"sqlite3-devel~3.39.3~150000.3.17.1", rls:"SLES15.0SP4"))) {
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
