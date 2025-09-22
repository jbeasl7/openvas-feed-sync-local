# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0229");
  script_cve_id("CVE-2015-3174", "CVE-2015-3175", "CVE-2015-3176", "CVE-2015-3178", "CVE-2015-3179", "CVE-2015-3180", "CVE-2015-3181");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0229");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0229.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15909");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.6.11_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313322");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313681");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313682");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313683");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313685");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313686");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313687");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=313688");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle package fixes security vulnerabilities:

In Moodle before 2.6.11, leaving gradebook feedback is a trusted action and
such capabilities in other modules already have an XSS mask, 'mod/quiz:grade'
was missing this flag (CVE-2015-3174).

In Moodle before 2.6.11, some error messages display a button to return to
the previous page. Redirecting to non-local referer should not be allowed as
it can potentially be used for phising (CVE-2015-3175).

In Moodle before 2.6.11, on sites with enabled self-registration, not
registered users can retrieve fullname of registered users if they know their
usernames (CVE-2015-3176).

In Moodle before 2.6.11, if a user who is not XSS-trusted attempts to insert
a script as part of the input text, it will be cleaned when displayed on the
Moodle website but may be displayed uncleaned in the external application
because external_format_text() cleans and formats text incorrectly when
returning it from Web Services (CVE-2015-3178).

In Moodle before 2.6.11, when self-registration is enabled and a user's
account was suspended after creating the account but before actually
confirming it, the user is still able to login when confirming their email,
but only once (CVE-2015-3179).

In Moodle before 2.6.11, if a user is enrolled in the course but his
enrollment is suspended, they can not access the course but still were able
to see the course structure in the navigation block (CVE-2015-3180).

In Moodle before 2.6.11, users with the revoked capability
'moodle/user:manageownfiles' are still able to upload private files using a
deprecated function in Web Services (CVE-2015-3181).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.11~1.mga4", rls:"MAGEIA4"))) {
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
