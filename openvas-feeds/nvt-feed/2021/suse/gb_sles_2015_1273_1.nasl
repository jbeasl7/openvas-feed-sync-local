# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1273.1");
  script_cve_id("CVE-2014-8964", "CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-3152");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 13:51:20 +0000 (Fri, 24 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1273-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151273-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936409");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2015:1273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:
 * Logjam attack: mysql uses 512 bit dh groups in SSL [bnc#934789]
 * CVE-2015-3152: mysql --ssl does not enforce SSL [bnc#924663]
 * CVE-2014-8964: heap buffer overflow [bnc#906574]
 * CVE-2015-2325: heap buffer overflow in compile_branch() [bnc#924960]
 * CVE-2015-2326: heap buffer overflow in pcre_compile2() [bnc#924961]
 * CVE-2015-0501: unspecified vulnerability related to Server:Compiling (CPU April 2015)
 * CVE-2015-2571: unspecified vulnerability related to Server:Optimizer (CPU April 2015)
 * CVE-2015-0505: unspecified vulnerability related to Server:DDL (CPU April 2015)
 * CVE-2015-0499: unspecified vulnerability related to Server:Federated (CPU April 2015)
 * CVE-2015-2568: unspecified vulnerability related to Server:Security:Privileges (CPU April 2015)
 * CVE-2015-2573: unspecified vulnerability related to Server:DDL (CPU April 2015)
 * CVE-2015-0433: unspecified vulnerability related to Server:InnoDB:DML (CPU April 2015)
 * CVE-2015-0441: unspecified vulnerability related to Server:Security:Encryption (CPU April 2015)");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.20~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.20~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.20~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.20~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.20~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.20~18.1", rls:"SLES12.0"))) {
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
