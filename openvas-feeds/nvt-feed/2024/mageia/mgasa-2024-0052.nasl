# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0052");
  script_cve_id("CVE-2021-32850");
  script_tag(name:"creation_date", value:"2024-03-01 04:12:42 +0000 (Fri, 01 Mar 2024)");
  script_version("2024-03-01T05:06:51+0000");
  script_tag(name:"last_modification", value:"2024-03-01 05:06:51 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 19:19:59 +0000 (Thu, 02 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0052");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0052.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32896");
  script_xref(name:"URL", value:"https://github.com/sympa-community/sympa/releases/tag/6.2.72");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sympa' package(s) announced via the MGASA-2024-0052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sympa 6.2.72 fixes many bugs, including the security one related in
CVE-2021-32850
It is required to manually run sympa upgrade after get this update");

  script_tag(name:"affected", value:"'sympa' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"sympa", rpm:"sympa~6.2.72~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sympa-mysql", rpm:"sympa-mysql~6.2.72~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sympa-postgresql", rpm:"sympa-postgresql~6.2.72~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sympa-www", rpm:"sympa-www~6.2.72~4.mga9", rls:"MAGEIA9"))) {
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
