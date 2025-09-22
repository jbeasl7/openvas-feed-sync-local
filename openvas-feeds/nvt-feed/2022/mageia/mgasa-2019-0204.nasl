# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0204");
  script_cve_id("CVE-2019-10164");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-27 14:42:08 +0000 (Thu, 27 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0204");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0204.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24996");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1949/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql11' package(s) announced via the MGASA-2019-0204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user could create a stack-based buffer overflow by
changing their own password to a purpose-crafted value. In addition to
the ability to crash the PostgreSQL server, this could be further
exploited to execute arbitrary code as the PostgreSQL operating system
account.

Additionally, a rogue server could send a specifically crafted message
during the SCRAM authentication process and cause a libpq-enabled client
to either crash or execute arbitrary code as the client's operating
system account. (CVE-2019-10164)

More than 25 other bugs have been fixed too, see referenced release
notes.");

  script_tag(name:"affected", value:"'postgresql11' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg11_6", rpm:"lib64ecpg11_6~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg11_6", rpm:"libecpg11_6~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11", rpm:"postgresql11~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-contrib", rpm:"postgresql11-contrib~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-devel", rpm:"postgresql11-devel~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-docs", rpm:"postgresql11-docs~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-pl", rpm:"postgresql11-pl~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-plperl", rpm:"postgresql11-plperl~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-plpgsql", rpm:"postgresql11-plpgsql~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-plpython", rpm:"postgresql11-plpython~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-plpython3", rpm:"postgresql11-plpython3~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-pltcl", rpm:"postgresql11-pltcl~11.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql11-server", rpm:"postgresql11-server~11.4~1.mga7", rls:"MAGEIA7"))) {
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
