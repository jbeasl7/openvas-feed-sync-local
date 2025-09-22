# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131146");
  script_cve_id("CVE-2015-5332", "CVE-2015-5335", "CVE-2015-5336", "CVE-2015-5337", "CVE-2015-5338", "CVE-2015-5339", "CVE-2015-5340", "CVE-2015-5341", "CVE-2015-5342");
  script_tag(name:"creation_date", value:"2015-12-08 09:03:39 +0000 (Tue, 08 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-24 19:35:53 +0000 (Wed, 24 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0464)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0464");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0464.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17280");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.8.9_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=322852");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323229");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323230");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323231");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323232");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323233");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323234");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323235");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323236");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=323237");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0464 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.8.9, if guest access is open on the site,
unauthenticated users can store Atto draft data through the editor
autosave area, which could be exploited in a denial of service attack
(CVE-2015-5332).

In Moodle before 2.8.9, due to a CSRF issue in the site registration form,
it is possible to trick a site admin into sending aggregate stats to an
arbitrary domain. The attacker can send the admin a link to a site
registration form that will display the correct URL but, if submitted,
will register with another hub (CVE-2015-5335).

In Moodle before 2.8.9, the standard survey module is vulnerable to XSS
attack by students who fill the survey (CVE-2015-5336).

In Moodle before 2.8.9, there was a reflected XSS vulnerability in the
Flowplayer flash video player (CVE-2015-5337).

In Moodle before 2.8.9, password-protected lesson modules are subject to a
CSRF vulnerability in the lesson login form (CVE-2015-5338).

In Moodle before 2.8.9, through web service core_enrol_get_enrolled_users
it is possible to retrieve list of course participants who would not be
visible when using web site (CVE-2015-5339).

In Moodle before 2.8.9, logged in users who do not have capability 'View
available badges without earning them' can still access the full list of
badges (CVE-2015-5340).

In Moodle before 2.8.9, the SCORM module allows to bypass access
restrictions based on date and lets users view the SCORM contents
(CVE-2015-5341).

In Moodle before 2.8.9, the choice module closing date can be bypassed,
allowing users to delete or submit new responses after the choice module
was closed (CVE-2015-5342).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.9~1.mga5", rls:"MAGEIA5"))) {
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
