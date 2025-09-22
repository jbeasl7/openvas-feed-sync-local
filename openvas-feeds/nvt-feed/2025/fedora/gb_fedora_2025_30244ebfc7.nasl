# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3024410198102997");
  script_cve_id("CVE-2025-40909");
  script_tag(name:"creation_date", value:"2025-07-14 04:18:53 +0000 (Mon, 14 Jul 2025)");
  script_version("2025-07-14T05:43:40+0000");
  script_tag(name:"last_modification", value:"2025-07-14 05:43:40 +0000 (Mon, 14 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-30244ebfc7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-30244ebfc7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-30244ebfc7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369463");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the FEDORA-2025-30244ebfc7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixes CVE-2025-40909 - Clone dirhandles without fchdir");

  script_tag(name:"affected", value:"'perl' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Attribute-Handlers", rpm:"perl-Attribute-Handlers~1.03~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-AutoLoader", rpm:"perl-AutoLoader~5.74~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-AutoSplit", rpm:"perl-AutoSplit~5.74~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-B", rpm:"perl-B~1.89~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-B-debuginfo", rpm:"perl-B-debuginfo~1.89~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Benchmark", rpm:"perl-Benchmark~1.25~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Class-Struct", rpm:"perl-Class-Struct~0.68~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Config-Extensions", rpm:"perl-Config-Extensions~0.03~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DBM_Filter", rpm:"perl-DBM_Filter~0.06~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Devel-Peek", rpm:"perl-Devel-Peek~1.34~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Devel-Peek-debuginfo", rpm:"perl-Devel-Peek-debuginfo~1.34~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Devel-SelfStubber", rpm:"perl-Devel-SelfStubber~1.06~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DirHandle", rpm:"perl-DirHandle~1.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Dumpvalue", rpm:"perl-Dumpvalue~2.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DynaLoader", rpm:"perl-DynaLoader~1.56~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-English", rpm:"perl-English~1.11~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Errno", rpm:"perl-Errno~1.38~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-Constant", rpm:"perl-ExtUtils-Constant~0.25~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.35~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-Miniperl", rpm:"perl-ExtUtils-Miniperl~1.14~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Fcntl", rpm:"perl-Fcntl~1.18~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Fcntl-debuginfo", rpm:"perl-Fcntl-debuginfo~1.18~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Basename", rpm:"perl-File-Basename~2.86~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Compare", rpm:"perl-File-Compare~1.100.800~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Copy", rpm:"perl-File-Copy~2.41~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-DosGlob", rpm:"perl-File-DosGlob~1.12~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-DosGlob-debuginfo", rpm:"perl-File-DosGlob-debuginfo~1.12~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Find", rpm:"perl-File-Find~1.44~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-stat", rpm:"perl-File-stat~1.14~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FileCache", rpm:"perl-FileCache~1.10~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FileHandle", rpm:"perl-FileHandle~2.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FindBin", rpm:"perl-FindBin~1.54~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GDBM_File", rpm:"perl-GDBM_File~1.24~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GDBM_File-debuginfo", rpm:"perl-GDBM_File-debuginfo~1.24~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Getopt-Std", rpm:"perl-Getopt-Std~1.14~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Hash-Util", rpm:"perl-Hash-Util~0.32~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Hash-Util-FieldHash", rpm:"perl-Hash-Util-FieldHash~1.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Hash-Util-FieldHash-debuginfo", rpm:"perl-Hash-Util-FieldHash-debuginfo~1.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Hash-Util-debuginfo", rpm:"perl-Hash-Util-debuginfo~0.32~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-I18N-Collate", rpm:"perl-I18N-Collate~1.02~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-I18N-LangTags", rpm:"perl-I18N-LangTags~0.45~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-I18N-Langinfo", rpm:"perl-I18N-Langinfo~0.24~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-I18N-Langinfo-debuginfo", rpm:"perl-I18N-Langinfo-debuginfo~0.24~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO", rpm:"perl-IO~1.55~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-debuginfo", rpm:"perl-IO-debuginfo~1.55~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IPC-Open3", rpm:"perl-IPC-Open3~1.22~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Locale-Maketext-Simple", rpm:"perl-Locale-Maketext-Simple~0.21~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Math-Complex", rpm:"perl-Math-Complex~1.62~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Memoize", rpm:"perl-Memoize~1.16~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.08~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NDBM_File", rpm:"perl-NDBM_File~1.17~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NDBM_File-debuginfo", rpm:"perl-NDBM_File-debuginfo~1.17~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NEXT", rpm:"perl-NEXT~0.69~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Net", rpm:"perl-Net~1.04~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ODBM_File", rpm:"perl-ODBM_File~1.18~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ODBM_File-debuginfo", rpm:"perl-ODBM_File-debuginfo~1.18~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Opcode", rpm:"perl-Opcode~1.65~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Opcode-debuginfo", rpm:"perl-Opcode-debuginfo~1.65~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-POSIX", rpm:"perl-POSIX~2.20~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-POSIX-debuginfo", rpm:"perl-POSIX-debuginfo~2.20~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Functions", rpm:"perl-Pod-Functions~1.14~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Html", rpm:"perl-Pod-Html~1.35~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Safe", rpm:"perl-Safe~2.46~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Search-Dict", rpm:"perl-Search-Dict~1.07~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SelectSaver", rpm:"perl-SelectSaver~1.02~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SelfLoader", rpm:"perl-SelfLoader~1.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Symbol", rpm:"perl-Symbol~1.09~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-Hostname", rpm:"perl-Sys-Hostname~1.25~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-Hostname-debuginfo", rpm:"perl-Sys-Hostname-debuginfo~1.25~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Term-Complete", rpm:"perl-Term-Complete~1.403~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Term-ReadLine", rpm:"perl-Term-ReadLine~1.17~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Test", rpm:"perl-Test~1.31~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Text-Abbrev", rpm:"perl-Text-Abbrev~1.02~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Thread", rpm:"perl-Thread~3.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Thread-Semaphore", rpm:"perl-Thread-Semaphore~2.13~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Tie", rpm:"perl-Tie~4.6~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Tie-File", rpm:"perl-Tie-File~1.09~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Tie-Memoize", rpm:"perl-Tie-Memoize~1.1~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time", rpm:"perl-Time~1.04~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.3401~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-Piece-debuginfo", rpm:"perl-Time-Piece-debuginfo~1.3401~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Unicode-UCD", rpm:"perl-Unicode-UCD~0.78~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-User-pwent", rpm:"perl-User-pwent~1.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-autouse", rpm:"perl-autouse~1.11~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~2.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-blib", rpm:"perl-blib~1.07~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugger", rpm:"perl-debugger~1.60~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debugsource", rpm:"perl-debugsource~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-deprecate", rpm:"perl-deprecate~0.04~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-diagnostics", rpm:"perl-diagnostics~1.40~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-encoding-warnings", rpm:"perl-encoding-warnings~0.14~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-fields", rpm:"perl-fields~2.27~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-filetest", rpm:"perl-filetest~1.03~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-if", rpm:"perl-if~0.61.000~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-interpreter", rpm:"perl-interpreter~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-interpreter-debuginfo", rpm:"perl-interpreter-debuginfo~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-less", rpm:"perl-less~0.03~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-lib", rpm:"perl-lib~0.65~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libnetcfg", rpm:"perl-libnetcfg~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs-debuginfo", rpm:"perl-libs-debuginfo~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-locale", rpm:"perl-locale~1.12~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-macros", rpm:"perl-macros~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-meta-notation", rpm:"perl-meta-notation~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-mro", rpm:"perl-mro~1.29~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-mro-debuginfo", rpm:"perl-mro-debuginfo~1.29~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-open", rpm:"perl-open~1.13~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-overload", rpm:"perl-overload~1.37~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-overloading", rpm:"perl-overloading~0.02~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ph", rpm:"perl-ph~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-sigtrap", rpm:"perl-sigtrap~1.10~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-sort", rpm:"perl-sort~2.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-subs", rpm:"perl-subs~1.04~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-tests", rpm:"perl-tests~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-utils", rpm:"perl-utils~5.40.2~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-vars", rpm:"perl-vars~1.05~518.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-vmsish", rpm:"perl-vmsish~1.04~518.fc42", rls:"FC42"))) {
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
