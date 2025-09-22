# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2690.1");
  script_cve_id("CVE-2017-9269", "CVE-2018-7685");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 17:17:54 +0000 (Mon, 26 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2690-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182690-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2018:2690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp, zypper, libsolv provides the following fixes:

Security fixes in libzypp:
CVE-2018-7685: PackageProvider: Validate RPMs before caching
 (bsc#1091624, bsc#1088705)

CVE-2017-9269: Be sure bad packages do not stay in the cache
 (bsc#1045735)

Changes in libzypp:
Update to version 17.6.4

Automatically fetch repository signing key from gpgkey url (bsc#1088037)

lsof: use '-K i' if lsof supports it (bsc#1099847,bsc#1036304)

Check for not imported keys after multi key import from rpmdb
 (bsc#1096217)

Flags: make it std=c++14 ready

Ignore /var, /tmp and /proc in zypper ps. (bsc#1096617)

Show GPGME version in log

Adapt to changes in libgpgme11-11.1.0 breaking the signature
 verification (bsc#1100427)

RepoInfo::provideKey: add report telling where we look for missing keys.

Support listing gpgkey URLs in repo files (bsc#1088037)

Add new report to request user approval for importing a package key

Handle http error 502 Bad Gateway in curl backend (bsc#1070851)

Add filesize check for downloads with known size (bsc#408814)

Removed superfluous space in translation (bsc#1102019)

Prevent the system from sleeping during a commit

RepoManager: Explicitly request repo2solv to generate application pseudo
 packages.

libzypp-devel should not require cmake (bsc#1101349)

Avoid zombies from ExternalProgram

Update ApiConfig

HardLocksFile: Prevent against empty commit without Target having been
 been loaded (bsc#1096803)

lsof: use '-K i' if lsof supports it (bsc#1099847)

Add filesize check for downloads with known size (bsc#408814)

Fix detection of metalink downloads and prevent aborting if a metalink
 file is larger than the expected data file.

Require libsolv-devel >= 0.6.35 during build (fixing bsc#1100095)

Make use of %license macro (bsc#1082318)

Security fix in zypper:
CVE-2017-9269: Improve signature check callback messages (bsc#1045735)

Changes in zypper:
Always set error status if any nr of unknown repositories are passed to
 lr and ref (bsc#1093103)

Notify user about unsupported rpm V3 keys in an old rpm database
 (bsc#1096217)

Detect read only filesystem on system modifying operations (fixes #199)

Use %license (bsc#1082318)

Handle repo aliases containing multiple ':' in the PackageArgs parser
 (bsc #1041178)

Fix broken display of detailed query results.

Fix broken search for items with a dash. (bsc#907538, bsc#1043166,
 bsc#1070770)

Disable repository operations when searching installed packages.
 (bsc#1084525)

Prevent nested calls to exit() if aborted by a signal. (bsc#1092413)

ansi.h: Prevent ESC sequence strings from going out of scope.
 (bsc#1092413)

Fix some translation errors.

Support listing gpgkey URLs in repo files (bsc#1088037)

Check for root privileges in zypper verify and si (bsc#1058515)

XML attribute `packages-to-change` added (bsc#1102429)

Add expert (allow-*) options to all installer commands (bsc#428822)

Sort ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libzypp, zypper' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debuginfo", rpm:"libsolv-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel-debuginfo", rpm:"libsolv-devel-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.6.4~3.10.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~17.6.4~3.10.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~17.6.4~3.10.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.6.4~3.10.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv-debuginfo", rpm:"python-solv-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.10~3.7.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.14.10~3.7.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.14.10~3.7.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.10~3.7.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv-debuginfo", rpm:"python3-solv-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.6.35~3.5.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv-debuginfo", rpm:"ruby-solv-debuginfo~0.6.35~3.5.2", rls:"SLES15.0"))) {
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
