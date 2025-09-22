# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0422.1");
  script_cve_id("CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-19 18:22:10 +0000 (Fri, 19 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0422-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180422-1.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076369");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003722.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2018:0422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql to version 5.5.59 fixes several issues.

These security issues were fixed:

- CVE-2018-2622: Vulnerability in the subcomponent: Server: DDL. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server (bsc#1076369)
- CVE-2018-2562: Vulnerability in the subcomponent: Server : Partition. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server as well as unauthorized update,
 insert or delete access to some of MySQL Server accessible data (bsc#1076369)
- CVE-2018-2640: Vulnerability in the subcomponent: Server: Optimizer. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server (bsc#1076369)
- CVE-2018-2665: Vulnerability in the subcomponent: Server: Optimizer. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server (bsc#1076369)
- CVE-2018-2668: Vulnerability in the subcomponent: Server: Optimizer. Easily
 exploitable vulnerability allowed low privileged attacker with network access
 via multiple protocols to compromise MySQL Server. Successful attacks of this
 vulnerability can result in unauthorized ability to cause a hang or frequently
 repeatable crash (complete DOS) of MySQL Server (bsc#1076369)

For additional changes please see [link moved to references]");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-32bit", rpm:"libmysql55client_r18-32bit~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18-x86", rpm:"libmysql55client_r18-x86~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.59~0.39.9.8", rls:"SLES11.0SP4"))) {
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
