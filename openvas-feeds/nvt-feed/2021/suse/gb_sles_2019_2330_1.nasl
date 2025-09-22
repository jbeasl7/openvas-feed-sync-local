# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2330.1");
  script_cve_id("CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-25 18:57:02 +0000 (Thu, 25 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2330-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192330-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143215");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005890.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb, mariadb-connector-c' package(s) announced via the SUSE-SU-2019:2330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb and mariadb-connector-c fixes the following issues:

mariadb:

- Update to version 10.2.25 (bsc#1136035)
- CVE-2019-2628: Fixed a remote denial of service by an privileged attacker (bsc#1136035).
- CVE-2019-2627: Fixed another remote denial of service by an privileged attacker (bsc#1136035).
- CVE-2019-2614: Fixed a potential remote denial of service by an privileged attacker (bsc#1136035).
- Fixed reading options for multiple instances if my${INSTANCE}.cnf is used (bsc#1132666).
- Adjust mysql-systemd-helper ('shutdown protected MySQL' section) so it checks both ping response
 and the pid in a process list as it can take some time till the process is terminated. Otherwise
 it can lead to 'found left-over process' situation when regular mariadb is started (bsc#1143215).

mariadb-connector-c:

- Update to version 3.1.2 (bsc#1136035)
- Moved libmariadb.pc from /usr/lib/pkgconfig to /usr/lib64/pkgconfig for x86_64 (bsc#1126088)");

  script_tag(name:"affected", value:"'mariadb, mariadb-connector-c' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~3.1.2~2.6.6", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb_plugins", rpm:"libmariadb_plugins~3.1.2~2.6.6", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.2.25~3.19.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.2.25~3.19.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.2.25~3.19.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.2.25~3.19.2", rls:"SLES12.0SP4"))) {
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
