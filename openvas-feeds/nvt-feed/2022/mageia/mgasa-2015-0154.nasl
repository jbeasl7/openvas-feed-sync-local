# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0154");
  script_cve_id("CVE-2015-0844");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0154");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0154.html");
  script_xref(name:"URL", value:"http://forums.wesnoth.org/viewtopic.php?t=41872");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15685");
  script_xref(name:"URL", value:"https://github.com/wesnoth/wesnoth/commit/af61f9fdd15cd439da9e2fe5fa39d174c923eaae");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wesnoth' package(s) announced via the MGASA-2015-0154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wesnoth packages fix security vulnerability

A severe security vulnerability in Battle of Wesnoth's game client was found
which could allow a malicious user to obtain personal files and information
from other players in networked multiplayer games using the built-in WML/Lua
API on any platform (CVE-2015-0844).

Upstream announces that all content currently on the official Wesnoth.org
add-ons server (add-ons.wesnoth.org) has been inspected to confirm that none
of it exploits this vulnerability.");

  script_tag(name:"affected", value:"'wesnoth' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"wesnoth", rpm:"wesnoth~1.10.7~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-data", rpm:"wesnoth-data~1.10.7~2.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wesnoth-server", rpm:"wesnoth-server~1.10.7~2.1.mga4", rls:"MAGEIA4"))) {
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
