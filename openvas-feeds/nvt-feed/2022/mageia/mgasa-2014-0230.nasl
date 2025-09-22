# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0230");
  script_cve_id("CVE-2014-0213", "CVE-2014-0214", "CVE-2014-0215", "CVE-2014-0216", "CVE-2014-0218");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0230");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0230.html");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.4.10_release_notes");
  script_xref(name:"URL", value:"http://docs.moodle.org/dev/Moodle_2.6.3_release_notes");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13369");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=260361");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=260362");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=260363");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=260364");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=260366");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2014-0230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.6.3, Session checking was not being performed correctly
in Assignment's quick-grading, allowing forged requests to be made
unknowingly by authenticated users (CVE-2014-0213).

In Moodle before 2.6.3, MoodleMobile web service tokens, created
automatically in login/token.php, were not expiring and were valid forever
(CVE-2014-0214).

In Moodle before 2.6.3, Some student details, including identities, were
included in assignment marking pages and would have been revealed to
screen readers or through code inspection (CVE-2014-0215).

In Moodle before 2.6.3, Access to files linked on HTML blocks on the My
home page was not being checked in the correct context, allowing access to
unauthenticated users (CVE-2014-0216).

In Moodle before 2.6.3, There was a lack of filtering in the URL
downloader repository that could have been exploited for XSS
(CVE-2014-0218).

The 2.4 branch of Moodle will no longer be supported as of approximately
June 2014, so the Moodle package has been upgraded to version 2.6.3 to fix
these issues.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.3~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.3~1.mga4", rls:"MAGEIA4"))) {
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
