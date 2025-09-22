# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131279");
  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_tag(name:"creation_date", value:"2016-03-31 05:05:04 +0000 (Thu, 31 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-11 14:31:22 +0000 (Mon, 11 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0119)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0119");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0119.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/03/15/5");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/03/16/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18013");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1317981");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.4.0.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.5.0.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.6.0.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.6.2.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.6.3.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.6.4.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.7.0.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.7.1.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.7.2.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.7.3.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.7.4.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cgit, git' package(s) announced via the MGASA-2016-0119 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a buffer overflow vulnerability possibly leading to remote code
execution in git. It can happen while pushing or cloning a repository with
a large filename or a large number of nested trees (CVE-2016-2315,
CVE-2016-2324).

The git package has been updated to version 2.7.4, which fixes this issue,
as well as several other bugs.

The cgit package bundles git, and its bundled copy of git has also been
updated to version 2.7.4.");

  script_tag(name:"affected", value:"'cgit, git' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cgit", rpm:"cgit~0.12~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-oldies", rpm:"git-core-oldies~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-prompt", rpm:"git-prompt~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitview", rpm:"gitview~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitweb", rpm:"gitweb~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64git-devel", rpm:"lib64git-devel~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit-devel", rpm:"libgit-devel~2.7.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~2.7.4~1.mga5", rls:"MAGEIA5"))) {
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
