# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0193");
  script_tag(name:"creation_date", value:"2024-05-27 04:12:12 +0000 (Mon, 27 May 2024)");
  script_version("2024-05-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-05-27 05:05:23 +0000 (Mon, 27 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0193");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0193.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33229");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.6.7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the MGASA-2024-0193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security update to the stable version 1.6 of Roundcube
Webmail.
Fix cross-site scripting (XSS) vulnerability in handling SVG animate
attributes.
Reported by Valentin T. and Lutz Wolf of CrowdStrike.
Fix cross-site scripting (XSS) vulnerability in handling list columns
from user preferences.
Reported by Huy Nguyen Pham Nhat.
Fix command injection via crafted im_convert_path/im_identify_path on
Windows.
Reported by Huy Nguyen Pham Nhat.
This version is considered stable and we recommend to update all
productive installations of Roundcube 1.6.x with it. Please do backup
your data before updating!");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.7~1.mga9", rls:"MAGEIA9"))) {
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
