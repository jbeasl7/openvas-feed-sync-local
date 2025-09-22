# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131310");
  script_cve_id("CVE-2016-2193", "CVE-2016-3065");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:12 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-13 18:09:25 +0000 (Wed, 13 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0136)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0136");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0136.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1656/");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-9-3-12.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-9-4-7.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18103");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9.3, postgresql9.4' package(s) announced via the MGASA-2016-0136 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated postgresql packages fix security vulnerabilities:

A vulnerability in PostgreSQL 9.3.x before 9.3.12 and 9.4.x before 9.4.7 leads
to potentially incorrect policies being applied in cases where role-specific
policies are used and a given query is planned under one role and then executed
under other roles, which could happen under security definer functions or when
a common user and query is planned initially and then re-used across multiple
SET ROLEs. Applying an incorrect policy may permit a user to complete
otherwise-forbidden reads and modifications. This affects only databases that
have used CREATE POLICY to define a row security policy (CVE-2016-2193).

A vulnerability was found in a way PostgreSQL 9.3.x before 9.3.12 and 9.4.x
before 9.4.7 uses pageinspect functions. Certain function arguments crashed
the server or disclosed a few bytes of server memory. The viability of attacks
that arrange for presence of confidential information in the disclosed bytes
was not ruled out. This affects only databases that have used 'CREATE
EXTENSION pageinspect' (CVE-2016-3065).");

  script_tag(name:"affected", value:"'postgresql9.3, postgresql9.4' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.3_6", rpm:"lib64ecpg9.3_6~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.4_6", rpm:"lib64ecpg9.4_6~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.3_5.6", rpm:"lib64pq9.3_5.6~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.3_6", rpm:"libecpg9.3_6~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.4_6", rpm:"libecpg9.4_6~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.3_5.6", rpm:"libpq9.3_5.6~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3", rpm:"postgresql9.3~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-contrib", rpm:"postgresql9.3-contrib~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-devel", rpm:"postgresql9.3-devel~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-docs", rpm:"postgresql9.3-docs~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pl", rpm:"postgresql9.3-pl~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plperl", rpm:"postgresql9.3-plperl~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpgsql", rpm:"postgresql9.3-plpgsql~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpython", rpm:"postgresql9.3-plpython~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pltcl", rpm:"postgresql9.3-pltcl~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-server", rpm:"postgresql9.3-server~9.3.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4", rpm:"postgresql9.4~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-contrib", rpm:"postgresql9.4-contrib~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-devel", rpm:"postgresql9.4-devel~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-docs", rpm:"postgresql9.4-docs~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pl", rpm:"postgresql9.4-pl~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plperl", rpm:"postgresql9.4-plperl~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpgsql", rpm:"postgresql9.4-plpgsql~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpython", rpm:"postgresql9.4-plpython~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pltcl", rpm:"postgresql9.4-pltcl~9.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-server", rpm:"postgresql9.4-server~9.4.7~1.mga5", rls:"MAGEIA5"))) {
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
