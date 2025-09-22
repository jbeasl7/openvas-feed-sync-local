# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123895");
  script_cve_id("CVE-2011-4088", "CVE-2012-1106");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 19:01:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-0841)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0841");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0841.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt, btparser, libreport, python-meh' package(s) announced via the ELSA-2012-0841 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"abrt
[2.0.8-6.0.1.el6]
- Add abrt-oracle-enterprise.patch to be product neutral
- Remove abrt-plugin-rhtsupport dependency for cli and desktop
- Make abrt Obsoletes/Provides abrt-plugin-rhtsupprot

[2.0.8-6]
- enable plugin services after install rhbz#820515
- Resolves: #820515

[2.0.8-5]
- removed the 'report problem with ABRT btn' rhbz#809587
- fixed double free
- fixed ccpp-install man page
- Resolves: #809587, #796216, #799027

[2.0.8-4]
- don't mark reports reported in post-create by mailx as reported
- Resolves: #803618

[2.0.8-3]
- fixed remote crash handling rhbz#800828
- Resolves: #800828

[2.0.8-2]
- updated translation
- added man page for a-a-analyze-vmcore
- minor fixes in kernel oops parser
- Related: #759375

[2.0.8-1]
- rebase to the latest upstream
- partly fixed problems with suided cores
- fixed confusing message about 'moved copy'
- properly enable daemons on update from previous version
- added default config file for mailx
- cli doesn't depend on python plugin
- properly init i18n all plugins
- added missing man page to abrt-cli
- added warning when user tries to report already reported problem again
- added vmcores plugin
- Resolves: #759375, #783450, #773242, #771597, #770357, #751068, #749100, #747624, #727494

btparser
[0.16-3]
- Report correct crash_function in the crash summary
 Resolves: rhbz#811147

[0.16-1]
- New upstream release
 Resolves: #768377

libreport
[2.0.9-5.0.1.el6]
- Add oracle-enterprise.patch
- Remove libreport-plugin-rhtsupport pkg

[2.0.9-5]
- rebuild due to rpmdiff
- Resolves: #823411

[2.0.9-4]
- fixed compatibility with bugzilla 4.2
- Resolves: #823411

[2.0.9-3]
- added notify-only option to mailx rhbz#803618
- Resolves: #803618

[2.0.9-2]
- minor fix in debuginfo downloader
- updated translations
- Related: #759377

[2.0.9-1]
- new upstream release
- fixed typos in man
- fixed handling of anaconda-tb file
- generate valid xml file
- Resolves: #759377, #758366, #746727

python-meh
[0.12.1-3]
- Add dbus-python and libreport to BuildRequires (vpodzime).
 Related: rhbz#796176

[0.12.1-2]
- Add %check
unset DISPLAY
 section to spec file (vpodzime).
 Resolves: rhbz#796176

[0.12.1-1]
- Adapt to new libreport API (vpodzime).
 Resolves: rhbz#769821
- Add info about environment variables (vpodzime).
 Resolves: rhbz#788577

[0.11-3]
- Move 'import rpm' to where its needed to avoid nameserver problems.
 Resolves: rhbz#749330

[0.11-2]
- Change dependency to libreport-* (mtoman)
 Resolves: rhbz#730924
- Add abrt-like information to bug reports (vpodzime).
 Resolves: rhbz#728871");

  script_tag(name:"affected", value:"'abrt, btparser, libreport, python-meh' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.0.8~6.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btparser", rpm:"btparser~0.16~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btparser-devel", rpm:"btparser-devel~0.16~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btparser-python", rpm:"btparser-python~0.16~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.0.9~5.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-meh", rpm:"python-meh~0.12.1~3.el6", rls:"OracleLinux6"))) {
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
