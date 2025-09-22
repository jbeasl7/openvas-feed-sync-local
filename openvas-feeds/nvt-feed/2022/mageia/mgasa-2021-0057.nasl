# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0057");
  script_cve_id("CVE-2019-2708");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 17:37:28 +0000 (Fri, 26 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2021-0057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0057");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0057.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27960");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OQFKX6NKU2DCW5CTCHQSOJJDFVRVTPO6/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'db53' package(s) announced via the MGASA-2021-0057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability in the Data Store component of Oracle Berkeley DB. Easily
exploitable vulnerability allows low privileged attacker having Local Logon
privilege with logon to the infrastructure where Data Store executes to
compromise Data Store. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial DOS) of Data
Store (CVE-2019-2708).");

  script_tag(name:"affected", value:"'db53' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"db53", rpm:"db53~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53-utils", rpm:"db53-utils~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"db53_recover", rpm:"db53_recover~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3", rpm:"lib64db5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-devel", rpm:"lib64db5.3-devel~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64db5.3-static-devel", rpm:"lib64db5.3-static-devel~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbcxx5.3", rpm:"lib64dbcxx5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbjava5.3", rpm:"lib64dbjava5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbsql5.3", rpm:"lib64dbsql5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbtcl5.3", rpm:"lib64dbtcl5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3", rpm:"libdb5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-devel", rpm:"libdb5.3-devel~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdb5.3-static-devel", rpm:"libdb5.3-static-devel~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbcxx5.3", rpm:"libdbcxx5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbjava5.3", rpm:"libdbjava5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbsql5.3", rpm:"libdbsql5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbtcl5.3", rpm:"libdbtcl5.3~5.3.28~17.1.mga7", rls:"MAGEIA7"))) {
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
