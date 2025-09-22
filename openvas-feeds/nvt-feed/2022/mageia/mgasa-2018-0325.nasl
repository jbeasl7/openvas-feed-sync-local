# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0325");
  script_cve_id("CVE-2018-1999023");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-20 16:21:38 +0000 (Thu, 20 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0325");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0325.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/07/22/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23338");
  script_xref(name:"URL", value:"https://github.com/wesnoth/wesnoth/blob/1.14.4/changelog.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wesnoth' package(s) announced via the MGASA-2018-0325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Battle for Wesnoth Project version 1.7.0 through 1.14.3 contains a Code
Injection vulnerability in the Lua scripting engine that can result in code
execution outside the sandbox. This attack appear to be exploitable via
Loading specially-crafted saved games, networked games, replays, and player
content (CVE-2018-1999023).

This is fixed in version 1.14.4, together with several non-security-related
bug fixes and enhancements.");

  script_tag(name:"affected", value:"'wesnoth' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.14.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-data", rpm:"wesnoth-data~1.14.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-server", rpm:"wesnoth-server~1.14.4~1.mga6", rls:"MAGEIA6"))) {
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
