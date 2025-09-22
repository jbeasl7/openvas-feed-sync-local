# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122873");
  script_cve_id("CVE-2015-7545");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:41 +0000 (Fri, 05 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-2515)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2515");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2515.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git19-git' package(s) announced via the ELSA-2015-2515 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.9.4-3.1]
- fix arbitrary code execution via crafted URLs
 Resolves: #1273889

[1.9.4-3]
- fix CVE-2014-9390
 Resolves: rhbz#1220552");

  script_tag(name:"affected", value:"'git19-git' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"git19-emacs-git", rpm:"git19-emacs-git~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-emacs-git-el", rpm:"git19-emacs-git-el~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git", rpm:"git19-git~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-all", rpm:"git19-git-all~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-cvs", rpm:"git19-git-cvs~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-daemon", rpm:"git19-git-daemon~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-email", rpm:"git19-git-email~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-gui", rpm:"git19-git-gui~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-svn", rpm:"git19-git-svn~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-gitk", rpm:"git19-gitk~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-gitweb", rpm:"git19-gitweb~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-perl-Git", rpm:"git19-perl-Git~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-perl-Git-SVN", rpm:"git19-perl-Git-SVN~1.9.4~3.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"git19-emacs-git", rpm:"git19-emacs-git~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-emacs-git-el", rpm:"git19-emacs-git-el~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git", rpm:"git19-git~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-all", rpm:"git19-git-all~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-bzr", rpm:"git19-git-bzr~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-cvs", rpm:"git19-git-cvs~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-daemon", rpm:"git19-git-daemon~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-email", rpm:"git19-git-email~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-gui", rpm:"git19-git-gui~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-hg", rpm:"git19-git-hg~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-git-svn", rpm:"git19-git-svn~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-gitk", rpm:"git19-gitk~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-gitweb", rpm:"git19-gitweb~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-perl-Git", rpm:"git19-perl-Git~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git19-perl-Git-SVN", rpm:"git19-perl-Git-SVN~1.9.4~3.el7.1", rls:"OracleLinux7"))) {
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
