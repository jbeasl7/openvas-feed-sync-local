# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0116");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0116)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0116");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0116.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14516");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15644");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'setup' package(s) announced via the MGASA-2015-0116 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been identified in Mageia 4's setup package where the
/etc/shadow and /etc/gshadow files containing password hashes were created
with incorrect permissions, making them world-readable (mga#14516).

This update fixes this issue by enforcing that those files are owned by
the root user and shadow group, and are only readable by those two entities.

Note that this issue only affected new Mageia 4 installations. Systems
that were updated from previous Mageia versions were not affected.

UPDATE: This update has since been removed as it still created rpmnew files
 and allowed users to unintentionally remove existing users by applying
 it. A better fix has since been found and will be pushed separately
 (mga#15644)");

  script_tag(name:"affected", value:"'setup' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"setup", rpm:"setup~2.7.20~9.4.mga4", rls:"MAGEIA4"))) {
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
