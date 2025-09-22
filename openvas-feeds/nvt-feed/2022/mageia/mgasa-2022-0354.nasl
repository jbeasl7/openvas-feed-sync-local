# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0354");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-35256");
  script_tag(name:"creation_date", value:"2022-10-03 04:31:23 +0000 (Mon, 03 Oct 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 14:52:20 +0000 (Thu, 21 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0354");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0354.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30887");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.20.1");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/september-2022-security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2022-0354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DNS rebinding in --inspect on macOS (CVE-2022-32212)
Bypass via obs-fold mechanic (CVE-2022-32213)
HTTP Request Smuggling Due to Incorrect Parsing of Header Fields
(CVE-2022-35256)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~14.20.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~14.20.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~14.20.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~14.20.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~6.14.17~1.14.20.1.2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~8.4.371.23.1.mga8~5.1.mga8", rls:"MAGEIA8"))) {
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
