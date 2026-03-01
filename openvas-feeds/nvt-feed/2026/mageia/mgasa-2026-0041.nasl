# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0041");
  script_cve_id("CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005", "CVE-2026-2006", "CVE-2026-2007");
  script_tag(name:"creation_date", value:"2026-02-18 04:49:39 +0000 (Wed, 18 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0041");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0041.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35133");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-182-178-1612-1516-and-1421-released-3235/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql15' package(s) announced via the MGASA-2026-0041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PostgreSQL oidvector discloses a few bytes of memory. (CVE-2026-2003)
PostgreSQL intarray missing validation of type of input to selectivity
estimator executes arbitrary code. (CVE-2026-2004)
PostgreSQL pgcrypto heap buffer overflow executes arbitrary code.
(CVE-2026-2005)
PostgreSQL missing validation of multibyte character length executes
arbitrary code. (CVE-2026-2006)
PostgreSQL pg_trgm heap buffer overflow writes pattern onto server
memory. (CVE-2026-2007");

  script_tag(name:"affected", value:"'postgresql15' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg15_6", rpm:"lib64ecpg15_6~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg15_6", rpm:"libecpg15_6~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pl", rpm:"postgresql15-pl~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpgsql", rpm:"postgresql15-plpgsql~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython3", rpm:"postgresql15-plpython3~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.16~1.mga9", rls:"MAGEIA9"))) {
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
