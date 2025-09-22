# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0308");
  script_cve_id("CVE-2014-3541", "CVE-2014-3542", "CVE-2014-3543", "CVE-2014-3544", "CVE-2014-3545", "CVE-2014-3546", "CVE-2014-3547", "CVE-2014-3548", "CVE-2014-3551", "CVE-2014-3553");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0308");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0308.html");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.6.4_release_notes");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13759");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264262");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264263");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264264");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264265");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264266");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264267");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264268");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264269");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264270");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=264273");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2014-0308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.6.4, serialised data passed by repositories could
potentially contain objects defined by add-ons that could include executable
code (CVE-2014-3541).

In Moodle before 2.6.4, it was possible for manipulated XML files passed from
LTI servers to be interpreted by Moodle to allow access to server-side files
(CVE-2014-3542).

In Moodle before 2.6.4, it was possible for manipulated XML files to be
uploaded to the IMSCC course format or the IMSCP resource to allow access to
server-side files (CVE-2014-3543).

In Moodle before 2.6.4, filtering of the Skype profile field was not removing
potentially harmful code (CVE-2014-3544).

In Moodle before 2.6.4, it was possible to inject code into Calculated
questions that would be executed on the server (CVE-2014-3545).

In Moodle before 2.6.4, it was possible to get limited user information,
such as user name and courses, by manipulating the URL of profile and notes
pages (CVE-2014-3546).

In Moodle before 2.6.4, the details of badges from external sources were not
being filtered (CVE-2014-3547).

In Moodle before 2.6.4, content of exception dialogues presented from AJAX
calls was not being escaped before being presented to users (CVE-2014-3548).

In Moodle before 2.6.4, fields in rubrics were not being correctly filtered
(CVE-2014-3551).

In Moodle before 2.6.4, forum was allowing users who were members of more
than one group to post to all groups without the capability to access all
groups (CVE-2014-3553).

The moodle package has been updated to version 2.6.4, to fix these issues
and other bugs.");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.4~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.4~1.mga4", rls:"MAGEIA4"))) {
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
