# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3593.1");
  script_cve_id("CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077", "CVE-2020-16590", "CVE-2020-16591", "CVE-2020-16592", "CVE-2020-16593", "CVE-2020-16598", "CVE-2020-16599", "CVE-2020-35448", "CVE-2020-35493", "CVE-2020-35496", "CVE-2020-35507", "CVE-2021-20197", "CVE-2021-20284", "CVE-2021-3487");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-25 18:38:54 +0000 (Mon, 25 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3593-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3593-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213593-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184794");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-November/009687.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2021:3593-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

Update to binutils 2.37:

* The GNU Binutils sources now requires a C99 compiler and library to
 build.
* Support for the arm-symbianelf format has been removed.
* Support for Realm Management Extension (RME) for AArch64 has been
 added.
* A new linker option '-z report-relative-reloc' for x86 ELF targets
 has been added to report dynamic relative relocations.
* A new linker option '-z start-stop-gc' has been added to disable
 special treatment of __start_*/__stop_* references when
 --gc-sections.
* A new linker options '-Bno-symbolic' has been added which will
 cancel the '-Bsymbolic' and '-Bsymbolic-functions' options.
* The readelf tool has a new command line option which can be used to
 specify how the numeric values of symbols are reported.
 --sym-base=0<pipe>8<pipe>10<pipe>16 tells readelf to display the values in base 8,
 base 10 or base 16. A sym base of 0 represents the default action
 of displaying values under 10000 in base 10 and values above that in
 base 16.
* A new format has been added to the nm program. Specifying
 '--format=just-symbols' (or just using -j) will tell the program to
 only display symbol names and nothing else.
* A new command line option '--keep-section-symbols' has been added to
 objcopy and strip. This stops the removal of unused section symbols
 when the file is copied. Removing these symbols saves space, but
 sometimes they are needed by other tools.
* The '--weaken', '--weaken-symbol' and '--weaken-symbols' options
 supported by objcopy now make undefined symbols weak on targets that
 support weak symbols.
* Readelf and objdump can now display and use the contents of .debug_sup
 sections.
* Readelf and objdump will now follow links to separate debug info
 files by default. This behaviour can be stopped via the use of the
 new '-wN' or '--debug-dump=no-follow-links' options for readelf and
 the '-WN' or '--dwarf=no-follow-links' options for objdump. Also
 the old behaviour can be restored by the use of the
 '--enable-follow-debug-links=no' configure time option.

 The semantics of the =follow-links option have also been slightly
 changed. When enabled, the option allows for the loading of symbol
 tables and string tables from the separate files which can be used
 to enhance the information displayed when dumping other sections,
 but it does not automatically imply that information from the
 separate files should be displayed.

 If other debug section display options are also enabled (eg
 '--debug-dump=info') then the contents of matching sections in both
 the main file and the separate debuginfo file *will* be displayed.
 This is because in most cases the debug section will only be present
 in one of the files.

 If however non-debug section display options are enabled (eg
 '--sections') then the contents of matching parts of the separate
 debuginfo file will *not* be displayed. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~9.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~9.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~9.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~9.39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~9.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~9.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~9.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~9.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~9.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~9.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~9.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~9.39.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.37~9.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.37~9.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf-nobfd0", rpm:"libctf-nobfd0~2.37~9.39.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libctf0", rpm:"libctf0~2.37~9.39.1", rls:"SLES12.0SP5"))) {
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
