# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120527");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_tag(name:"creation_date", value:"2015-09-08 11:28:36 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-306)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-306");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-306.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9' package(s) announced via the ALAS-2014-306 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stack-based buffer overflow flaws were found in the date/time implementation of PostgreSQL. An authenticated database user could provide a specially crafted date/time value that, when processed, could cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0063)

Multiple integer overflow flaws, leading to heap-based buffer overflows, were found in various type input functions in PostgreSQL. An authenticated database user could possibly use these flaws to crash PostgreSQL or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0064)

Multiple potential buffer overflow flaws were found in PostgreSQL. An authenticated database user could possibly use these flaws to crash PostgreSQL or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2014-0065)

It was found that granting an SQL role to a database user in a PostgreSQL database without specifying the 'ADMIN' option allowed the grantee to remove other users from their granted role. An authenticated database user could use this flaw to remove a user from an SQL role which they were granted access to. (CVE-2014-0060)

A flaw was found in the validator functions provided by PostgreSQL's procedural languages (PLs). An authenticated database user could possibly use this flaw to escalate their privileges. (CVE-2014-0061)

A race condition was found in the way the CREATE INDEX command performed multiple independent lookups of a table that had to be indexed. An authenticated database user could possibly use this flaw to escalate their privileges. (CVE-2014-0062)

It was found that the chkpass extension of PostgreSQL did not check the return value of the crypt() function. An authenticated database user could possibly use this flaw to crash PostgreSQL via a null pointer dereference. (CVE-2014-0066)");

  script_tag(name:"affected", value:"'postgresql9' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql9", rpm:"postgresql9~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-contrib", rpm:"postgresql9-contrib~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-debuginfo", rpm:"postgresql9-debuginfo~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-devel", rpm:"postgresql9-devel~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-docs", rpm:"postgresql9-docs~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-libs", rpm:"postgresql9-libs~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-plperl", rpm:"postgresql9-plperl~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-plpython", rpm:"postgresql9-plpython~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-pltcl", rpm:"postgresql9-pltcl~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-server", rpm:"postgresql9-server~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-test", rpm:"postgresql9-test~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9-upgrade", rpm:"postgresql9-upgrade~9.2.7~1.40.amzn1", rls:"AMAZON"))) {
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
