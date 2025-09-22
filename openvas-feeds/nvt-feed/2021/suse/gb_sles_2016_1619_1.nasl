# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1619.1");
  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668", "CVE-2016-2047");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-22 13:07:25 +0000 (Fri, 22 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1619-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161619-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980904");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002128.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2016:1619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mariadb was updated to version 10.0.25 to fix 25 security issues.

These security issues were fixed:
- CVE-2016-0505: Unspecified vulnerability allowed remote authenticated users to affect availability via unknown vectors related to Options (bsc#980904).
- CVE-2016-0546: Unspecified vulnerability allowed local users to affect confidentiality, integrity, and availability via unknown vectors related to Client (bsc#980904).
- CVE-2016-0596: Unspecified vulnerability allowed remote authenticated users to affect availability via vectors related to DML (bsc#980904).
- CVE-2016-0597: Unspecified vulnerability allowed remote authenticated users to affect availability via unknown vectors related to Optimizer (bsc#980904).
- CVE-2016-0598: Unspecified vulnerability allowed remote authenticated users to affect availability via vectors related to DML (bsc#980904).
- CVE-2016-0600: Unspecified vulnerability allowed remote authenticated users to affect availability via unknown vectors related to InnoDB (bsc#980904).
- CVE-2016-0606: Unspecified vulnerability allowed remote authenticated users to affect integrity via unknown vectors related to encryption (bsc#980904).
- CVE-2016-0608: Unspecified vulnerability allowed remote authenticated users to affect availability via vectors related to UDF (bsc#980904).
- CVE-2016-0609: Unspecified vulnerability allowed remote authenticated users to affect availability via unknown vectors related to privileges (bsc#980904).
- CVE-2016-0616: Unspecified vulnerability allowed remote authenticated users to affect availability via unknown vectors related to Optimizer (bsc#980904).
- CVE-2016-0640: Unspecified vulnerability allowed local users to affect integrity and availability via vectors related to DML (bsc#980904).
- CVE-2016-0641: Unspecified vulnerability allowed local users to affect confidentiality and availability via vectors related to MyISAM (bsc#980904).
- CVE-2016-0642: Unspecified vulnerability allowed local users to affect integrity and availability via vectors related to Federated (bsc#980904).
- CVE-2016-0643: Unspecified vulnerability allowed local users to affect confidentiality via vectors related to DML (bsc#980904).
- CVE-2016-0644: Unspecified vulnerability allowed local users to affect availability via vectors related to DDL (bsc#980904).
- CVE-2016-0646: Unspecified vulnerability allowed local users to affect availability via vectors related to DML (bsc#980904).
- CVE-2016-0647: Unspecified vulnerability allowed local users to affect availability via vectors related to FTS (bsc#980904).
- CVE-2016-0648: Unspecified vulnerability allowed local users to affect availability via vectors related to PS (bsc#980904).
- CVE-2016-0649: Unspecified vulnerability allowed local users to affect availability via vectors related to PS (bsc#980904).
- CVE-2016-0650: Unspecified vulnerability allowed local users to affect availability via ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.25~20.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.25~20.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.25~20.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.25~20.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.25~20.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.25~20.6.1", rls:"SLES12.0"))) {
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
