# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120168");
  script_cve_id("CVE-2014-0067", "CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0242", "CVE-2015-0243", "CVE-2015-0244");
  script_tag(name:"creation_date", value:"2015-09-08 11:19:03 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 20:18:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-492)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-492");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-492.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql92' package(s) announced via the ALAS-2015-492 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow flaw was found in the way PostgreSQL handled certain numeric formatting. An authenticated database user could use a specially crafted timestamp formatting template to cause PostgreSQL to crash or, under certain conditions, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0241)

A buffer overflow flaw was found in the PostgreSQL's internal printf() implementation. An authenticated database user could use a specially crafted string in an SQL query to cause PostgreSQL to crash or, potentially, lead to privilege escalation. (CVE-2015-0242)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto module. An authenticated database user could use this flaw to cause PostgreSQL to crash or, potentially, execute arbitrary code with the permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in way PostgreSQL handled certain errors during that were generated during protocol synchronization. An authenticated database user could use this flaw to inject queries into an existing connection. (CVE-2015-0244)

The 'make check' command for the test suites in PostgreSQL 9.3.3 and earlier does not properly invoke initdb to specify the authentication requirements for a database cluster to be used for the tests, which allows local users to gain privileges by leveraging access to this cluster. (CVE-2014-0067)

An information leak flaw was found in the way certain the PostgreSQL database server handled certain error messages. An authenticated database user could possibly obtain the results of a query they did not have privileges to execute by observing the constraint violation error messages produced when the query was executed. (CVE-2014-8161)");

  script_tag(name:"affected", value:"'postgresql92' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql92", rpm:"postgresql92~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-contrib", rpm:"postgresql92-contrib~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-debuginfo", rpm:"postgresql92-debuginfo~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-devel", rpm:"postgresql92-devel~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-docs", rpm:"postgresql92-docs~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-libs", rpm:"postgresql92-libs~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-plperl", rpm:"postgresql92-plperl~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-plpython", rpm:"postgresql92-plpython~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-pltcl", rpm:"postgresql92-pltcl~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-server", rpm:"postgresql92-server~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-server-compat", rpm:"postgresql92-server-compat~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql92-test", rpm:"postgresql92-test~9.2.10~1.49.amzn1", rls:"AMAZON"))) {
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
