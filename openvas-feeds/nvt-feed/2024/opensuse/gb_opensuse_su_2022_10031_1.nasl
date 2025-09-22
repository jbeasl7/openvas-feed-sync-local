# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833299");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2012-3386");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for wdiff (openSUSE-SU-2022:10031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10031-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RHVSBRLGJ5C5MYYVH2AXVEQBTRVMVFRD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wdiff'
  package(s) announced via the openSUSE-SU-2022:10031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wdiff fixes the following issues:
  This update ships wdiff.
  Updated to 1.2.2:

  * Updated Vietnamese, Swedish, Estonian, Chinese (traditional),
         Brazilian Portuguese and Russian translations.

  * Updated gnulib.

  * Used more recent autotools: autoconf 2.69 and automake 1.14.1.
  updated to 1.2.1:

  * Added Esperanto translation.

  * Updated Czech, German, Spanish, Finnish, Galician, Italian, Dutch,
         Polish, Slovenian, Serbian, Swedish, Ukrainian and Vietnamese
         translations.

  * Updated gnulib.

  * Recreated build system using recent versions of autotools. This will
         avoid security issues in 'make distcheck' target. (CVE-2012-3386)
  updated to 1.1.2:

  * Backport gnulib change to deal with removal of gets function. This is
         a build-time-only fix. (Mentioned in Fedora bug #821791)

  * Added Serbian translation.

  * Updated Danish and Vietnamese translations.

  * Work around a bug in the formatting of the man page. (Debian bug
         #669340)

  * Updated Czech, German, Spanish, Finnish, Dutch, Polish, Slovenian,
         Swedish and Ukrainian translations.

  * Fix several issue with the use of screen in the test suite.

  * Allow WDIFF_PAGER to override PAGER environment variable.

  * Do not autodetect less, so we don't auto-enable less-mode. This should
         improve things for UTF8 text. (Savannah bug #34224) Less-mode is
         considered deprecated, as it isn't fit for multi-byte encodings.
         Nevertheless it can still be enabled on the command line.

  * Introduces use of ngettext to allow correct handling of plural forms
  updated to 1.0.1:

  * Updated Polish, Ukrainian, Slovenian, Dutch, Finnish, Swedish and
         Czech translations

  * Changed major version to 1 to reflect maturity of the package

  * Updated Dutch, French, Danish and Slovenian translations

  * Added Ukrainian translation

  * Improved error reporting in case a child process has problems

  * Added tests to the test suite

  * Updated gnulib
  updated to 0.6.5:

  * Never initialize or deinitialize terminals, as we do no cursor movement

  * Deprecated --no-init-term (-K) command line option

  * Avoid relative path in man pages

  * Updated gnulib, might be particularly important for uClibc users
  updated to 0.6.4:

  * Updated Catalan translations

  * Updated gnulib
  update to 0.6.3:

  * `wdiff -d' to read input from single unified diff, perhaps stdin.

  * Updated texinfo documentation taking experimental switch ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'wdiff' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wdiff", rpm:"wdiff~1.2.2~bp154.2.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdiff-lang", rpm:"wdiff-lang~1.2.2~bp154.2.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdiff", rpm:"wdiff~1.2.2~bp154.2.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdiff-lang", rpm:"wdiff-lang~1.2.2~bp154.2.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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