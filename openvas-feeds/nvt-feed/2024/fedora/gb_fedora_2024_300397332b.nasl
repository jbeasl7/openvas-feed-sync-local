# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.30039733298");
  script_tag(name:"creation_date", value:"2024-11-21 04:08:37 +0000 (Thu, 21 Nov 2024)");
  script_version("2024-11-22T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-22 05:05:35 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-300397332b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-300397332b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-300397332b");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'llvm-test-suite' package(s) announced via the FEDORA-2024-300397332b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Remove ClamAV subdirectory because of viruses in input files:

These were the findings:

```
MultiSource/Applications/ClamAV/inputs/rtf-test/rtf1.rtf: Eicar-Signature
MultiSource/Applications/ClamAV/inputs/clam.zip: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/docCLAMexe.rtf: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/Doc11.rtf: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/Doc1.rtf: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/clam.cab: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/Doc2.rtf: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/clam.exe.bz2: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/doc3.rtf: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/clam.exe: Clamav.Test.File-6
MultiSource/Applications/ClamAV/inputs/rtf-test/Doc22.rtf: Clamav.Test.File-6
```


----

Remove broken links in source tarball

Before it wasn't possible to pass `-DTEST_SUITE_SUBDIRS=CTMark` to cmake
when configuring the llvm-test-suite:

```
-- Adding directory CTMark
CMake Error at CTMark/CMakeLists.txt:1 (add_subdirectory):
 add_subdirectory given source '7zip' which is not an existing directory.

CMake Error at CTMark/CMakeLists.txt:5 (add_subdirectory):
 add_subdirectory given source 'lencod' which is not an existing directory.
```

The llvm-test-suite command script `pkg_test_suite.sh` removes
directories with BAD or unreviewed licenses. Currently this leaves at
least two directories in a broken state:

```
/usr/share/llvm-test-suite/CTMark/7zip -> ../MultiSource/Benchmarks/7zip
/usr/share/llvm-test-suite/CTMark/lencod -> ../MultiSource/Applications/JM/lencod
```

In both cases the link target is non-existent.

Therefore I find any broken symbolic links, remove them and adapt the
`CMakeLists.txt` to not have the `add_subdirectory(broken_link)` entry in
it. Here's an excerpt of what the `pkg_test_suite.sh` script shows when
running as a proof of the work it does now.

```
++ find test-suite-19.1.0.src -type l '!' -exec test -e '{}' ',' -print
+ broken_symlinks='test-suite-19.1.0.src/CTMark/7zip
test-suite-19.1.0.src/CTMark/lencod'
+ for f in $broken_symlinks
+ test -L test-suite-19.1.0.src/CTMark/7zip
+ rm -fv test-suite-19.1.0.src/CTMark/7zip
removed 'test-suite-19.1.0.src/CTMark/7zip'
++ dirname test-suite-19.1.0.src/CTMark/7zip
+ basedir=test-suite-19.1.0.src/CTMark
++ basename test-suite-19.1.0.src/CTMark/7zip
+ dir=7zip
+ cmake_file=test-suite-19.1.0.src/CTMark/CMakeLists.txt
+ test -f test-suite-19.1.0.src/CTMark/CMakeLists.txt
+ sed -i 's/add_subdirectory(7zip)//g' test-suite-19.1.0.src/CTMark/CMakeLists.txt
+ for f in $broken_symlinks
+ test -L test-suite-19.1.0.src/CTMark/lencod
+ rm -fv test-suite-19.1.0.src/CTMark/lencod
removed 'test-suite-19.1.0.src/CTMark/lencod'
++ dirname test-suite-19.1.0.src/CTMark/lencod
+ ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'llvm-test-suite' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"llvm-test-suite", rpm:"llvm-test-suite~18.1.8~3.fc40", rls:"FC40"))) {
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
