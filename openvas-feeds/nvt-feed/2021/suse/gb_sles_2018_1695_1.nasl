# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1695.1");
  script_cve_id("CVE-2018-1115");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-14 18:03:19 +0000 (Thu, 14 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1695-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181695-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091610");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004192.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1851/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-6-9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql96' package(s) announced via the SUSE-SU-2018:1695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PostgreSQL was updated to 9.6.9 fixing bugs and security issues:

Release notes:

- [links moved to references]

 A dump/restore is not required for those running 9.6.X.
 However, if you use the adminpack extension, you should update
 it as per the first changelog entry below.
 Also, if the function marking mistakes mentioned in the second
 and third changelog entries below affect you, you will want to
 take steps to correct your database catalogs.

Security issue fixed:

- CVE-2018-1115: Remove public execute privilege
 from contrib/adminpack's pg_logfile_rotate() function
 pg_logfile_rotate() is a deprecated wrapper for the core
 function pg_rotate_logfile(). When that function was changed
 to rely on SQL privileges for access control rather than a
 hard-coded superuser check, pg_logfile_rotate() should have
 been updated as well, but the need for this was missed. Hence,
 if adminpack is installed, any user could request a logfile
 rotation, creating a minor security issue.
 After installing this update, administrators should update
 adminpack by performing ALTER EXTENSION adminpack UPDATE in
 each database in which adminpack is installed. (bsc#1091610)");

  script_tag(name:"affected", value:"'postgresql96' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.9~3.19.1", rls:"SLES12.0SP3"))) {
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
