# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123994");
  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:56:01 +0000 (Thu, 08 Feb 2024)");

  script_name("Oracle: Security Advisory (ELSA-2012-0103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0103");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0103.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail' package(s) announced via the ELSA-2012-0103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.4.8-5.0.1.el5_7.13]
- Remove Redhat splash screen images

[1.4.8-5.13]
- fix typo in CVE-20210-4555 patch

[1.4.8-5.12]
- patch for CVE-2010-2813 was not complete

[1.4.8-5.11]
- fix: CVE-2010-1637 : Port-scans via non-standard POP3 server ports in
 Mail Fetch plugin
- fix: CVE-2010-2813 : DoS (disk space consumption) by random IMAP login
 attempts with 8-bit characters in the password
- fix: CVE-2010-4554 : Prone to clickjacking attacks
- fix: CVE-2010-4555 : Multiple XSS flaws
[tag handling]
- fix: CVE-2011-2752 : CRLF injection vulnerability
- fix: CVE-2011-2753 : CSRF in the empty trash feature and in Index Order page");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~18.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.0.1.el5_7.13", rls:"OracleLinux5"))) {
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
