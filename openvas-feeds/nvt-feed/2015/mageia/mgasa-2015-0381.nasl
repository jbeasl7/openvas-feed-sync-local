# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130010");
  script_cve_id("CVE-2015-5264", "CVE-2015-5265", "CVE-2015-5266", "CVE-2015-5267", "CVE-2015-5268", "CVE-2015-5269");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:29 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-24 20:03:03 +0000 (Wed, 24 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0381");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0381.html");
  script_xref(name:"URL", value:"https://bitbucket.org/oasychev/moodle-plugins/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16767");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.8.8_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=319884");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320287");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320289");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320290");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320291");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320292");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=320293");
  script_xref(name:"URL", value:"https://moodle.org/plugins/view/qtype_oumultiresponse");
  script_xref(name:"URL", value:"https://moodle.org/plugins/view/theme_uikit");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.8.8, completed and graded lesson activity was not
protected against making new attempts to answer some questions, so students
could re-attempt answering questions in the lesson (CVE-2015-5264).

In Moodle before 2.8.8, users could delete files uploaded by other users in
wiki (CVE-2015-5265).

In Moodle before 2.8.8, meta course synchronisation enrols suspended students
as managers for a short period of time and causes large database growth. On
large installations, when the sync script takes a long time, suspended
students may get assigned a manager role in meta course for several minutes
(CVE-2015-5266)

In Moodle before 2.8.8, password recovery tokens can be guessed because of
php randomisation limitations (CVE-2015-5267).

In Moodle before 2.8.8, when viewing ratings, the group access was not
properly checked, allowing users from other groups to view ratings
(CVE-2015-5268).

In Moodle before 2.8.8, capability to manage groups does not have XSS risk,
however it was possible to add XSS to the grouping description
(CVE-2015-5269).

The moodle package has been updated to version 2.8.8, fixing these issues and
several other bugs.

Additionally, the preg plugin has been updated to version 2.8, and the OU
Multiple Response question type and UIkit theme have been added to the
package.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.8~1.mga5", rls:"MAGEIA5"))) {
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
