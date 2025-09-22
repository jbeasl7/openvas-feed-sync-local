# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122920");
  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_tag(name:"creation_date", value:"2016-04-06 11:32:59 +0000 (Wed, 06 Apr 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Oracle: Security Advisory (ELSA-2016-0594)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0594");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0594.html");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Changes/Harden_all_packages_with_position-independent_code");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphite2' package(s) announced via the ELSA-2016-0594 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.6-1]
- Related: rhbz#1309052 CVE-2016-1521 CVE-2016-1522 CVE-2016-1523 CVE-2016-1526

[1.3.5-1]
- Resolves: rhbz#1309052 CVE-2016-1521 CVE-2016-1522 CVE-2016-1523 CVE-2016-1526

[1.2.4-6]
- Rebuilt for [link moved to references]

[1.2.4-5]
- Rebuilt for [link moved to references]

[1.2.4-4]
- Rebuilt for Fedora 23 Change
 [link moved to references]

[1.2.4-3]
- Rebuilt for [link moved to references]

[1.2.4-2]
- Rebuilt for [link moved to references]

[1.2.4-1]
- New upstream release");

  script_tag(name:"affected", value:"'graphite2' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"graphite2", rpm:"graphite2~1.3.6~1.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphite2-devel", rpm:"graphite2-devel~1.3.6~1.el7_2", rls:"OracleLinux7"))) {
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
