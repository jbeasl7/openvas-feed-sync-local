# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833329");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32182");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 16:32:30 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:34 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for postfix (SUSE-SU-2023:3394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3394-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AHUV5YCFCRBL5YZJ6EQNXEQQZWNVKJVC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix'
  package(s) announced via the SUSE-SU-2023:3394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postfix fixes the following issues:

  * CVE-2023-32182: Fixed config_postfix SUSE specific script potentially bad
      /tmp file usage (bsc#1211196).

  * Update to from 3.7.2 to 3.7.3:

  * Fixes a bug where some messages were not delivered after 'warning:
      Unexpected record type 'X'. (bsc#1213515)

  ##");

  script_tag(name:"affected", value:"'postfix' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap", rpm:"postfix-ldap~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-ldap-debuginfo", rpm:"postfix-ldap-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb", rpm:"postfix-bdb-lmdb~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-lmdb-debuginfo", rpm:"postfix-bdb-lmdb-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debugsource", rpm:"postfix-bdb-debugsource~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql-debuginfo", rpm:"postfix-postgresql-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb-debuginfo", rpm:"postfix-bdb-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix", rpm:"postfix~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-bdb", rpm:"postfix-bdb~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-debugsource", rpm:"postfix-debugsource~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-mysql-debuginfo", rpm:"postfix-mysql-debuginfo~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postfix-doc", rpm:"postfix-doc~3.7.3~150500.3.5.1", rls:"openSUSELeap15.5"))) {
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