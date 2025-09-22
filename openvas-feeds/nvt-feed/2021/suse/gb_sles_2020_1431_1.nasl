# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1431.1");
  script_cve_id("CVE-2020-13249");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-08 16:49:00 +0000 (Mon, 08 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1431-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201431-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171550");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-May/006860.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-connector-c' package(s) announced via the SUSE-SU-2020:1431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb-connector-c fixes the following issues:

Security issue fixed:

- CVE-2020-13249: Fixed an improper validation of OK packets received from clients (bsc#1171550).

Non-security issues fixed:

- Update to release 3.1.8 (bsc#1171550)
 * CONC-304: Rename the static library to libmariadb.a and other libmariadb files in a consistent manner
 * CONC-441: Default user name for C/C is wrong if login user is different from effective user
 * CONC-449: Check $MARIADB_HOME/my.cnf in addition to $MYSQL_HOME/my.cnf
 * CONC-457: mysql_list_processes crashes in unpack_fields
 * CONC-458: mysql_get_timeout_value crashes when used improper
 * CONC-464: Fix static build for auth_gssapi_client plugin");

  script_tag(name:"affected", value:"'mariadb-connector-c' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~3.1.8~2.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb_plugins", rpm:"libmariadb_plugins~3.1.8~2.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadb3", rpm:"libmariadb3~3.1.8~2.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadb_plugins", rpm:"libmariadb_plugins~3.1.8~2.15.1", rls:"SLES12.0SP5"))) {
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
