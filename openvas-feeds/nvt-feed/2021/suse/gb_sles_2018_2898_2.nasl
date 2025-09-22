# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2898.2");
  script_cve_id("CVE-2018-12470", "CVE-2018-12471", "CVE-2018-12472");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-21 23:49:41 +0000 (Wed, 21 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2898-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2898-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182898-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977043");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smt, yast2-smt' package(s) announced via the SUSE-SU-2018:2898-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yast2-smt to 3.0.14 and smt to 3.0.37 fixes the following issues:

These security issues were fixed in SMT:

- CVE-2018-12471: Xml External Entity processing in the RegistrationSharing
 modules allowed to read arbitrary file read (bsc#1103809).
- CVE-2018-12470: SQL injection in RegistrationSharing module allows remote
 attackers to run arbitrary SQL statements (bsc#1103810).
- CVE-2018-12472: Authentication bypass in sibling check facilitated further
 attacks on SMT (bsc#1104076).

SUSE would like to thank Jake Miller for reporting these issues to us.

These non-security issues were fixed in SMT:

- Fix cron jobs randomization (bsc#1097560)
- Fix duplicate migration paths (bsc#1097824)

This non-security issue was fixed in yast2-smt:

- Remove cron job rescheduling (bsc#1097560)
- Added missing translation marks (bsc#1037811)
- Explicitly mention 'Organization Credentials' (fate#321759)
- Rearrange the SMT set-up dialog (bsc#977043)
- Make the Filter button default (bsc#1006984)
- Prevent exiting the repo selection dialog via hitting Enter in
 the repository filter (bsc#1006984)
- report when error occurs during repo mirroring (bsc#1006989)
- Use TextEntry-based filter for repos (fate#319777)");

  script_tag(name:"affected", value:"'smt, yast2-smt' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"res-signingkeys", rpm:"res-signingkeys~3.0.37~52.23.6", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smt", rpm:"smt~3.0.37~52.23.6", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"smt-support", rpm:"smt-support~3.0.37~52.23.6", rls:"SLES12.0SP2"))) {
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
