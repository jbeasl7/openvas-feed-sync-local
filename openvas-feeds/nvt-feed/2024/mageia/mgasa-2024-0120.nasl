# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0120");
  script_cve_id("CVE-2024-1597");
  script_tag(name:"creation_date", value:"2024-04-12 04:12:12 +0000 (Fri, 12 Apr 2024)");
  script_version("2024-04-12T15:39:03+0000");
  script_tag(name:"last_modification", value:"2024-04-12 15:39:03 +0000 (Fri, 12 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-25 16:42:20 +0000 (Mon, 25 Mar 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0120");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0120.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33051");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/04/02/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-jdbc' package(s) announced via the MGASA-2024-0120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if
using PreferQueryMode=SIMPLE. Note this is not the default. In the
default mode there is no vulnerability. A placeholder for a numeric
value must be immediately preceded by a minus. There must be a second
placeholder for a string value after the first placeholder, both must be
on the same line. By constructing a matching string payload, the
attacker can inject SQL to alter the query,bypassing the protections
that parameterized queries bring against SQL Injection attacks.
(CVE-2024-1597)");

  script_tag(name:"affected", value:"'postgresql-jdbc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql-jdbc", rpm:"postgresql-jdbc~42.5.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-jdbc-javadoc", rpm:"postgresql-jdbc-javadoc~42.5.6~1.mga9", rls:"MAGEIA9"))) {
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
