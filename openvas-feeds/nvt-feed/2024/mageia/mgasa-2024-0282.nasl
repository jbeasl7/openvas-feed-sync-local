# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0282");
  script_cve_id("CVE-2024-22018", "CVE-2024-22020", "CVE-2024-36137", "CVE-2024-36138", "CVE-2024-37372");
  script_tag(name:"creation_date", value:"2024-08-29 04:11:48 +0000 (Thu, 29 Aug 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0282)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0282");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0282.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33415");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.0.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.1.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.2.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.3.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.4.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.5.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.5.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v22.6.0");
  script_xref(name:"URL", value:"https://github.com/yarnpkg/yarn/releases/tag/v1.22.22");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs, yarnpkg' package(s) announced via the MGASA-2024-0282 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nodejs 22 is the new active LTS branch and 5 CVE are fixed.
CVE-2024-36138 - Bypass incomplete fix of CVE-2024-27980 (High)
CVE-2024-22020 - Bypass network import restriction via data URL (Medium)
CVE-2024-22018 - fs.lstat bypasses permission model (Low)
CVE-2024-36137 - fs.fchown/fchmod bypasses permission model (Low)
CVE-2024-37372 - Permission model improperly processes UNC paths (Low)
yarn package is updated with npm 10.8.2");

  script_tag(name:"affected", value:"'nodejs, yarnpkg' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~22.6.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~22.6.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~22.6.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~22.6.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~10.8.2~1.22.6.0.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~12.4.254.21.mga9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.22~0.10.8.2.1.mga9", rls:"MAGEIA9"))) {
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
