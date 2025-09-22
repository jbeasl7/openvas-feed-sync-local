# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0743.1");
  script_cve_id("CVE-2010-5298", "CVE-2012-5615", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-2494", "CVE-2014-3470", "CVE-2014-4207", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6474", "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6489", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559", "CVE-2014-6564", "CVE-2014-6568", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382", "CVE-2015-0391", "CVE-2015-0411", "CVE-2015-0432");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-01-22 22:12:53 +0000 (Thu, 22 Jan 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0743-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150743-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919229");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10016-release-notes/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001353.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2015:0743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mariadb was updated to version 10.0.16 to fix 40 security issues.

These security issues were fixed:
- CVE-2015-0411: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier, and 5.6.21 and earlier, allowed remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Server : Security : Encryption (bnc#915911).
- CVE-2015-0382: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allowed remote attackers to affect availability via unknown vectors related to Server : Replication, a different vulnerability than CVE-2015-0381 (bnc#915911).
- CVE-2015-0381: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allowed remote attackers to affect availability via unknown vectors related to Server : Replication, a different vulnerability than CVE-2015-0382 (bnc#915911).
- CVE-2015-0432: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier allowed remote authenticated users to affect availability via vectors related to Server : InnoDB : DDL : Foreign Key (bnc#915911).
- CVE-2014-6568: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier, and 5.6.21 and earlier, allowed remote authenticated users to affect availability via vectors related to Server : InnoDB : DML (bnc#915911).
- CVE-2015-0374: Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allowed remote authenticated users to affect confidentiality via unknown vectors related to Server : Security : Privileges : Foreign Key (bnc#915911).
- CVE-2014-6507: Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier, and 5.6.20 and earlier, allowed remote authenticated users to affect confidentiality, integrity, and availability via vectors related to SERVER:DML (bnc#915912).
- CVE-2014-6491: Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier and 5.6.20 and earlier allowed remote attackers to affect confidentiality, integrity, and availability via vectors related to SERVER:SSL:yaSSL, a different vulnerability than CVE-2014-6500 (bnc#915912).
- CVE-2014-6500: Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier, and 5.6.20 and earlier, allowed remote attackers to affect confidentiality, integrity, and availability via vectors related to SERVER:SSL:yaSSL, a different vulnerability than CVE-2014-6491 (bnc#915912).
- CVE-2014-6469: Unspecified vulnerability in Oracle MySQL Server 5.5.39 and eariler and 5.6.20 and earlier allowed remote authenticated users to affect availability via vectors related to SERVER:OPTIMIZER (bnc#915912).
- CVE-2014-6555: Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier and 5.6.20 and earlier allowed remote authenticated users to affect confidentiality, integrity, and availability via vectors related to SERVER:DML (bnc#915912).
- CVE-2014-6559: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.16~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.16~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.16~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.16~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.16~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.16~15.1", rls:"SLES12.0"))) {
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
