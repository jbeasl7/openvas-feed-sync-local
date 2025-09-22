# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0214.1");
  script_cve_id("CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307");
  script_tag(name:"creation_date", value:"2022-01-28 07:56:21 +0000 (Fri, 28 Jan 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-14 16:42:01 +0000 (Thu, 14 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0214-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220214-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194844");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/010127.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'log4j' package(s) announced via the SUSE-SU-2022:0214-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for log4j fixes the following issues:

- CVE-2022-23307: Fixed deserialization flaw in the chainsaw component of log4j leading to malicious code execution. (bsc#1194844)
- CVE-2022-23305: Fixed SQL injection when application is configured to use JDBCAppender. (bsc#1194843)
- CVE-2022-23302: Fixed remote code execution when application is configured to use JMSSink. (bsc#1194842)");

  script_tag(name:"affected", value:"'log4j' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"log4j", rpm:"log4j~1.2.17~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-manual", rpm:"log4j-manual~1.2.17~5.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"log4j", rpm:"log4j~1.2.17~5.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-manual", rpm:"log4j-manual~1.2.17~5.9.1", rls:"SLES15.0SP1"))) {
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
