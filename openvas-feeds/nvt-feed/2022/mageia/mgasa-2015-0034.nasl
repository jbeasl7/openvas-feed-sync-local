# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0034");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0034.html");
  script_xref(name:"URL", value:"http://freeciv.wikia.com/wiki/NEWS-2.4.2");
  script_xref(name:"URL", value:"http://freeciv.wikia.com/wiki/NEWS-2.4.3");
  script_xref(name:"URL", value:"http://freeciv.wikia.com/wiki/NEWS-2.4.4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14038");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15038");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeciv' package(s) announced via the MGASA-2015-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated freeciv packages to latest bugfix version, also fixing security vulnerability

Freeciv 2.4.1 in Mageia 4 was built against an embedded version of lua 5.1,
vulnerable to the following security issue:

A heap-based overflow vulnerability was found in the way Lua handles varargs
functions with many fixed parameters called with few arguments, leading to
application crashes or, potentially, arbitrary code execution (CVE-2014-5461,
mga#14038).

As of this update, Freeciv is now built against the patched system version
of lua 5.1.

This update also provides Freeciv 2.4.4, a maintenance release in the 2.4.x
stable branch with numerous bug fixes and minor new features.
See the referenced release notes for details.");

  script_tag(name:"affected", value:"'freeciv' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeciv", rpm:"freeciv~2.4.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-client", rpm:"freeciv-client~2.4.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-data", rpm:"freeciv-data~2.4.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-server", rpm:"freeciv-server~2.4.4~1.mga4", rls:"MAGEIA4"))) {
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
