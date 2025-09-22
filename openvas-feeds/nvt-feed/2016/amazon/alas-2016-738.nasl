# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120727");
  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0666", "CVE-2016-2047", "CVE-2016-3452", "CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-5444");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:21 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-738)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-738");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-738.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql55' package(s) announced via the ALAS-2016-738 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the MariaDB client library did not properly check host names against server identities noted in the X.509 certificates when establishing secure connections using TLS/SSL. A man-in-the-middle attacker could possibly use this flaw to impersonate a server to a client. (CVE-2016-2047)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via vectors related to UDF. (CVE-2016-0608)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to privileges. (CVE-2016-0609)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to Options. (CVE-2016-0505)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to InnoDB. (CVE-2016-0600)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0616)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows remote attackers to affect confidentiality via vectors related to Server: Security: Encryption. (CVE-2016-3452)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows local users to affect availability via vectors related to DDL. (CVE-2016-0644)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows local users to affect confidentiality, integrity, and availability via vectors related to Server: Parser. (CVE-2016-3477)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2016-0596)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0597)

Unspecified vulnerability in Oracle MySQL 5.5.47 and earlier allows local users to affect integrity and availability via vectors related to DML. (CVE-2016-0640)

Unspecified vulnerability in Oracle MySQL 5.5.49 and earlier allows remote authenticated users to affect availability via vectors related to Server: Types. (CVE-2016-3521)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows local users to affect integrity and availability via vectors related to Federated. (CVE-2016-0642)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows local users to affect confidentiality via vectors related to DML. (CVE-2016-0643)

Unspecified vulnerability in Oracle MySQL 5.5.48 and earlier allows local users to affect availability via vectors related to Security: Privileges. (CVE-2016-0666)

Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mysql55' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mysql-config", rpm:"mysql-config~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55", rpm:"mysql55~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-bench", rpm:"mysql55-bench~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-debuginfo", rpm:"mysql55-debuginfo~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-devel", rpm:"mysql55-devel~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded", rpm:"mysql55-embedded~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded-devel", rpm:"mysql55-embedded-devel~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-libs", rpm:"mysql55-libs~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-server", rpm:"mysql55-server~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-test", rpm:"mysql55-test~5.5.51~1.11.amzn1", rls:"AMAZON"))) {
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
