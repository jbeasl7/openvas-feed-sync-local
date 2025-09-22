# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0222");
  script_tag(name:"creation_date", value:"2022-06-10 04:28:34 +0000 (Fri, 10 Jun 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0222");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0222.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30502");
  script_xref(name:"URL", value:"https://github.com/ultrajson/ultrajson/releases/tag/5.3.0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/R3GHJVC47JEGKA6UDB2UE57K2NMY57RH/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-ujson' package(s) announced via the MGASA-2022-0222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benchmark refactor - argparse CLI.
Fix segmentation faults when errors occur while handling unserialisable
objects.
Fix segmentation fault when an exception is raised while converting a dict
key to a string.
Fix memory leak dumping on non-string dict keys - Fix ref counting on
repeated default function calls.
Remove redundant wheel dependency from pyproject.toml");

  script_tag(name:"affected", value:"'python-ujson' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-ujson", rpm:"python-ujson~5.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ujson", rpm:"python3-ujson~5.3.0~1.mga8", rls:"MAGEIA8"))) {
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
