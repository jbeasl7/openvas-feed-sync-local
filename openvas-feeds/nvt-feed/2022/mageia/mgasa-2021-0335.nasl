# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0335");
  script_cve_id("CVE-2021-26119", "CVE-2021-26120");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 12:56:29 +0000 (Fri, 26 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0335)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0335");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0335.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28996");
  script_xref(name:"URL", value:"https://github.com/smarty-php/smarty/releases/tag/v3.1.39");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2618");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-smarty' package(s) announced via the MGASA-2021-0335 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Smarty before 3.1.39 allows a Sandbox Escape because $smarty.template_object
can be accessed in sandbox mode (CVE-2021-26119).

Smarty before 3.1.39 allows code injection via an unexpected function name
after a {function name= substring (CVE-2021-26120).");

  script_tag(name:"affected", value:"'php-smarty' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-smarty", rpm:"php-smarty~3.1.39~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"php-smarty", rpm:"php-smarty~3.1.39~1.mga8", rls:"MAGEIA8"))) {
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
