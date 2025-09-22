# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833866");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-25147");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 19:42:25 +0000 (Wed, 17 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:59 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for apr (SUSE-SU-2023:0389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0389-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OGPECRBP6DD7JUZRKAPXR2B37ATR4POJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr'
  package(s) announced via the SUSE-SU-2023:0389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apr-util fixes the following issues:

  - CVE-2022-25147: Fixed a buffer overflow possible with specially crafted
       input during base64 encoding (bsc#1207866)");

  script_tag(name:"affected", value:"'apr' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"apr-util-debuginfo", rpm:"apr-util-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-debugsource", rpm:"apr-util-debugsource~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-devel", rpm:"apr-util-devel~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-mysql", rpm:"libapr-util1-dbd-mysql~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-mysql-debuginfo", rpm:"libapr-util1-dbd-mysql-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql", rpm:"libapr-util1-dbd-pgsql~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql-debuginfo", rpm:"libapr-util1-dbd-pgsql-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3", rpm:"libapr-util1-dbd-sqlite3~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3-debuginfo", rpm:"libapr-util1-dbd-sqlite3-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbm-db", rpm:"libapr-util1-dbm-db~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbm-db-debuginfo", rpm:"libapr-util1-dbm-db-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-debuginfo", rpm:"libapr-util1-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-debuginfo", rpm:"apr-util-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-debugsource", rpm:"apr-util-debugsource~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apr-util-devel", rpm:"apr-util-devel~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-mysql", rpm:"libapr-util1-dbd-mysql~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-mysql-debuginfo", rpm:"libapr-util1-dbd-mysql-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql", rpm:"libapr-util1-dbd-pgsql~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql-debuginfo", rpm:"libapr-util1-dbd-pgsql-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3", rpm:"libapr-util1-dbd-sqlite3~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3-debuginfo", rpm:"libapr-util1-dbd-sqlite3-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbm-db", rpm:"libapr-util1-dbm-db~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-dbm-db-debuginfo", rpm:"libapr-util1-dbm-db-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-util1-debuginfo", rpm:"libapr-util1-debuginfo~1.6.1~150300.18.5.1", rls:"openSUSELeap15.4"))) {
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