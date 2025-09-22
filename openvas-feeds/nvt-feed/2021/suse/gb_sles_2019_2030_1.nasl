# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2030.1");
  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-06 17:21:39 +0000 (Sun, 06 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2030-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2030-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192030-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp and libsolv, zypper' package(s) announced via the SUSE-SU-2019:2030-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp and libsolv fixes the following issues:

Security issues fixed:
CVE-2018-20532: Fixed NULL pointer dereference at ext/testcase.c
 (function testcase_read) (bsc#1120629).

CVE-2018-20533: Fixed NULL pointer dereference at ext/testcase.c
 (function testcase_str2dep_complex) in libsolvext.a (bsc#1120630).

CVE-2018-20534: Fixed illegal address access at src/pool.h (function
 pool_whatprovides) in libsolv.a (bsc#1120631).

Fixed bugs and enhancements:
make cleandeps jobs on patterns work (bnc#1137977)

Fixed an issue where libsolv failed to build against swig 4.0 by
 updating the version to 0.7.5 (bsc#1135749).

Virtualization host upgrade from SLES-15 to SLES-15-SP1 finished with
 wrong product name shown up (bsc#1131823).

Copy pattern categories from the rpm that defines the pattern
 (fate#323785).

Enhance scanning /sys for modaliases (bsc#1130161).

Prevent SEGV if the application sets an empty TextLocale (bsc#1127026).

Handle libgpgme error when gpg key is not completely read and user hits
 CTRL + C (bsc#1127220).

Added a hint when registration codes have expired (bsc#965786).

Adds a better handling of an error when verifying any repository medium
 (bsc#1065022).

Will now only write type field when probing (bsc#1114908).

Fixes an issue where zypper has showed the info message 'Installation
 aborted by user' while the installation was aborted by wicked
 (bsc#978193).

Suppresses reporting `/memfd:` pseudo files (bsc#1123843).

Fixes an issue where zypper was not able to install or uninstall
 packages when rpm is unavailable (bsc#1122471).

Fixes an issue where locks were ignored (bsc#1113296).

Simplify complex locks so zypper can display them (bsc#1112911).

zypper will now set `SYSTEMD_OFFLINE=1` during chrooted commits
 (bsc#1118758).

no-recommends: Nevertheless consider resolver namespaces (hardware,
 language,..supporting packages) (fate#325513).

Removes world-readable bit from /var/log/zypp (bsc#1099019).

Does no longer fail service-refresh on a empty repoindex.xml
 (bsc#1116840).

Fixes soname due to libsolv ABI changes (bsc#1115341).

Add infrastructure to flag specific packages to trigger a reboot needed
 hint (fate#326451).

This update for zypper 1.14.27 fixes the following issues:
bash-completion: add package completion for addlock (bsc#1047962)

bash-completion: fix incorrect detection of command names (bsc#1049826)
Offer to change the 'runSearchPackages' config option at the prompt
 (bsc#1119373, FATE#325599)

Prompt: provide a 'yes/no/always/never' prompt.

Prompt: support '#NUM' as answer to select the NUMth option...

Augeas: enable writing back changed option values (to ~/.zypper.conf)

removelocale: fix segfault

Move needs-restarting command to subpackage (fixes #254)

Allow empty string as argument (bsc#1125415)

Provide a way to delete cache for volatile repositories (bsc#1053177)

Adapt to boost-1.69 requiring ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libzypp and libsolv, zypper' package(s) on SUSE Linux Enterprise Installer 15, SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debuginfo", rpm:"libsolv-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel-debuginfo", rpm:"libsolv-devel-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-debugsource", rpm:"libyui-ncurses-pkg-debugsource~2.48.5.2~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-devel", rpm:"libyui-ncurses-pkg-devel~2.48.5.2~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-doc", rpm:"libyui-ncurses-pkg-doc~2.48.5.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg8", rpm:"libyui-ncurses-pkg8~2.48.5.2~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg8-debuginfo", rpm:"libyui-ncurses-pkg8-debuginfo~2.48.5.2~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-debugsource", rpm:"libyui-qt-pkg-debugsource~2.45.15.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-doc", rpm:"libyui-qt-pkg-doc~2.45.15.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg8", rpm:"libyui-qt-pkg8~2.45.15.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg8-debuginfo", rpm:"libyui-qt-pkg8-debuginfo~2.45.15.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.12.0~3.23.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~17.12.0~3.23.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~17.12.0~3.23.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.12.0~3.23.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv-debuginfo", rpm:"python-solv-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings", rpm:"yast2-pkg-bindings~4.0.13~3.7.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings-debuginfo", rpm:"yast2-pkg-bindings-debuginfo~4.0.13~3.7.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings-debugsource", rpm:"yast2-pkg-bindings-debugsource~4.0.13~3.7.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.28~3.18.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.14.28~3.18.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.14.28~3.18.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.28~3.18.6", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-backend-zypp", rpm:"PackageKit-backend-zypp~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-backend-zypp-debuginfo", rpm:"PackageKit-backend-zypp-debuginfo~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-debuginfo", rpm:"PackageKit-debuginfo~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-debugsource", rpm:"PackageKit-debugsource~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-devel", rpm:"PackageKit-devel~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-devel-debuginfo", rpm:"PackageKit-devel-debuginfo~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-lang", rpm:"PackageKit-lang~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-18", rpm:"libpackagekit-glib2-18~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-18-debuginfo", rpm:"libpackagekit-glib2-18-debuginfo~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-devel", rpm:"libpackagekit-glib2-devel~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-devel", rpm:"libyui-qt-pkg-devel~2.45.15.2~3.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-PackageKitGlib-1_0", rpm:"typelib-1_0-PackageKitGlib-1_0~1.1.10~4.10.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv-debuginfo", rpm:"python3-solv-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.7.5~3.12.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv-debuginfo", rpm:"ruby-solv-debuginfo~0.7.5~3.12.2", rls:"SLES15.0"))) {
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
