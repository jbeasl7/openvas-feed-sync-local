# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0280");
  script_cve_id("CVE-2013-4313", "CVE-2013-4341");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0280)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0280");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0280.html");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.6_release_notes");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11212");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=237413");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=238396");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=238399");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2013-0280 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

Null characters were allowed in query strings in Moodle before 2.4.6, which
caused sql statements to terminate and fail, potentially allowing sql
injection in Moodle's SQL Server driver (CVE-2013-4313).

Links to external blogs were not being adequately cleaned in Moodle before
2.4.6, potentially allowing for XSS attacks (CVE-2013-4341).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.6~1.mga3", rls:"MAGEIA3"))) {
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
