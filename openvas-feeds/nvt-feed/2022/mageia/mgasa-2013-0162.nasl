# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0162");
  script_cve_id("CVE-2013-2079", "CVE-2013-2080", "CVE-2013-2081", "CVE-2013-2082", "CVE-2013-2083");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0162.html");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.4_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228536");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228930");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228931");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228933");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228934");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=228935");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2013-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The assignment module in Moodle before 2.4.4 was not checking capabilities
for users downloading all assignments as a zip (CVE-2013-2079).

The Gradebook's Overview report in Moodle before 2.4.4 was showing grade
totals that may have incorrectly included hidden grades (CVE-2013-2080).

When registering a site on a hub (not Moodle.net) site in Moodle before
2.4.4, information was being sent to the hub regardless of settings chosen
(CVE-2013-2081).

There was no check of permissions for viewing comments on blog posts in
Moodle before 2.4.4 (CVE-2013-2082).

Form elements named using a specific naming scheme were not being filtered
correctly in Moodle before 2.4.4 (CVE-2013-2083).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.4.4~1.1.mga3", rls:"MAGEIA3"))) {
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
