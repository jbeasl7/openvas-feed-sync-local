# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1279.1");
  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0666", "CVE-2016-2047");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-22 13:25:23 +0000 (Fri, 22 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1279-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161279-1.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-48.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-49.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976341");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2016:1279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mysql was updated to version 5.5.49 to fix 13 security issues.

These security issues were fixed:
- CVE-2016-0644: Unspecified vulnerability allowed local users to affect availability via vectors related to DDL (bsc#976341).
- CVE-2016-0646: Unspecified vulnerability allowed local users to affect availability via vectors related to DML (bsc#976341).
- CVE-2016-0647: Unspecified vulnerability allowed local users to affect availability via vectors related to FTS (bsc#976341).
- CVE-2016-0640: Unspecified vulnerability allowed local users to affect integrity and availability via vectors related to DML (bsc#976341).
- CVE-2016-0641: Unspecified vulnerability allowed local users to affect confidentiality and availability via vectors related to MyISAM (bsc#976341).
- CVE-2016-0642: Unspecified vulnerability allowed local users to affect integrity and availability via vectors related to Federated (bsc#976341).
- CVE-2016-0643: Unspecified vulnerability allowed local users to affect confidentiality via vectors related to DML (bsc#976341).
- CVE-2016-0666: Unspecified vulnerability allowed local users to affect availability via vectors related to Security: Privileges (bsc#976341).
- CVE-2016-0651: Unspecified vulnerability allowed local users to affect availability via vectors related to Optimizer (bsc#976341).
- CVE-2016-0650: Unspecified vulnerability allowed local users to affect availability via vectors related to Replication (bsc#976341).
- CVE-2016-0648: Unspecified vulnerability allowed local users to affect availability via vectors related to PS (bsc#976341).
- CVE-2016-0649: Unspecified vulnerability allowed local users to affect availability via vectors related to PS (bsc#976341).
- CVE-2016-2047: The ssl_verify_server_cert function in sql-common/client.c did not properly verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allowed man-in-the-middle attackers to spoof SSL servers via a '/CN=' string in a field in a certificate, as demonstrated by '/OU=/CN=bar.com/CN=foo.com (bsc#963806).

More details are available at
- [links moved to references]");

  script_tag(name:"affected", value:"'mysql' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-32bit", rpm:"libmysql55client_r18-32bit~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-x86", rpm:"libmysql55client_r18-x86~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.49~0.20.1", rls:"SLES11.0SP4"))) {
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
