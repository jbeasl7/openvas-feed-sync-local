# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0360");
  script_cve_id("CVE-2022-37706");
  script_tag(name:"creation_date", value:"2022-10-10 04:44:17 +0000 (Mon, 10 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 20:30:47 +0000 (Wed, 04 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2022-0360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0360");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0360.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30868");
  script_xref(name:"URL", value:"https://git.enlightenment.org/enlightenment/enlightenment/commit/cc7faeccf77fef8b0ae70e312a21e4cde087e141");
  script_xref(name:"URL", value:"https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'enlightenment' package(s) announced via the MGASA-2022-0360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated enlightenment package to fix the security vulnerability,
CVE-2022-37706 that would allow an user to gain root privileges.");

  script_tag(name:"affected", value:"'enlightenment' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"enlightenment", rpm:"enlightenment~0.24.2~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enlightenment-devel", rpm:"enlightenment-devel~0.24.2~2.1.mga8", rls:"MAGEIA8"))) {
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
