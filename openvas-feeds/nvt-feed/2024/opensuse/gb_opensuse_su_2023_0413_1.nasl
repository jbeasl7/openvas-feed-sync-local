# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833345");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-39070");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 14:20:39 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:30:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for cppcheck (openSUSE-SU-2023:0413-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0413-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JPXYQJRDWA7KRE6MM4XEMXQLBO4V7XED");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cppcheck'
  package(s) announced via the openSUSE-SU-2023:0413-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cppcheck fixes the following issues:

  - CVE-2023-39070: Fixed heap use-after-free in removeContradiction()
       (boo#1215233)

  - update to 2.12.1:

  * Support importing projects with project-name

  - update to 2.12.0:

  * uselessOverride finds overriding functions that either duplicate code
         from or delegate back to the base class implementation

  * knownPointerToBool finds pointer to bool conversions that are always
         true or false

  * truncLongCastAssignment and truncLongCastReturn check additional
         types, including float/double/long double

  * duplInheritedMember also reports duplicated member functions

  * constParameter*/constVariable* checks find more instances of
         pointers/references that can be const, e.g. when calling library
         functions

  * Write how many checkers was activated after a run

  * Added --checkers-report that can be used to generate a report in a
         file that shows what checkers was activated and disabled

  * The qmake build system has been deprecated and will be removed in a
         future version.

  * Command-line option '--template

  - update to 2.11:

  * pop_back on empty container is UB

  * Improve useStlAlgorithm check to handle many more conditions in the
         loop for any_of, all_of and none_of algorithms

  * ValueFlow can evaluate the return value of functions even when
         conditionals are used

  * ValueFlow will now forward the container sizes being returned from a
         function

  * ValueFlow can infer possible values from possible symbolic values

  * Improve valueflow after pushing to container

  * The new option --check-level= has been added that controls how much
         checking is made by Cppcheck. The default checking level is 'normal'.
         If you feel that you can wait longer on results you can use

  - -check-level=exhaustive.

  * It is no longer necessary to run '--check-config' to get detailed
         'missingInclude' and 'missingIncludeSystem' messages. They will always
         be issued in the regular analysis if 'missingInclude' is enabled.

  * 'missingInclude' and 'missingIncludeSystem' are reported with '-j' is
           1 and processes are used in the backend (default in non-Windows
         binaries)

  * 'missingInclude' and 'missingIncludeSystem' will now cause the
         '--error-exitcode' to be applied

  * '--enable=information' will no longer implicitly enable
         'missingInclude' starting with 2.1 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'cppcheck' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cppcheck", rpm:"cppcheck~2.12.1~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-gui", rpm:"cppcheck-gui~2.12.1~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck", rpm:"cppcheck~2.12.1~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-gui", rpm:"cppcheck-gui~2.12.1~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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