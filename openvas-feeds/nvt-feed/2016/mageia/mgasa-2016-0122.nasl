# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131276");
  script_cve_id("CVE-2016-2151", "CVE-2016-2152", "CVE-2016-2153", "CVE-2016-2154", "CVE-2016-2155", "CVE-2016-2156", "CVE-2016-2157", "CVE-2016-2158", "CVE-2016-2159", "CVE-2016-2190");
  script_tag(name:"creation_date", value:"2016-03-31 05:05:01 +0000 (Thu, 31 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-23 18:46:30 +0000 (Mon, 23 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0122");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0122.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18048");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.8.11_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=329783");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330173");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330174");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330175");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330176");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330177");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330178");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330179");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330180");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330181");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=330182");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2016-0122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.8.11, teachers who otherwise were not supposed to see
students' emails could see them in the participants list (CVE-2016-2151).

In Moodle before 2.8.11, Moodle traditionally trusted content from
external DB, however it was decided that external datasources may not be
aware of web security practices and data could cause problems after
importing to Moodle (CVE-2016-2152).

In Moodle before 2.8.11, a user with higher permissions could be tricked
into clicking a link which would result in Reflected XSS in mod_data
advanced search (CVE-2016-2153).

In Moodle before 2.8.11, users without capability to view hidden courses
but with capability to subscribe to Event Monitor rules could see the
names of hidden courses (CVE-2016-2154).

In Moodle before 2.8.11, the Non-Editing Instructor role can edit the
exclude checkbox in the Single View grade report (CVE-2016-2155).

In Moodle before 2.8.11, users without the capability to view hidden
acitivites could still see associated calendar events via web services,
via the external function get_calendar_events (CVE-2016-2156).

In Moodle before 2.8.11, CSRF is possible on the Assignment plugin admin
page, however an exploit is unlikely to benefit anybody and can easily be
reversed (CVE-2016-2157).

In Moodle before 2.8.11, enumeration of course category details is
possible without authentication (CVE-2016-2158).

In Moodle before 2.8.11, students were able to add assignment submissions
after the due date through web service, via the external function
mod_assign_save_submission (CVE-2016-2159).

In Moodle before 2.8.11, when following external links that were added
with the _blank target, a referer header would be added (CVE-2016-2190).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.11~1.mga5", rls:"MAGEIA5"))) {
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
