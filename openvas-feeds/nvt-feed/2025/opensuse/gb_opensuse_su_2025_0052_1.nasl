# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0052.1");
  script_cve_id("CVE-2025-24359");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0052-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0052-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/S3ET4NHUOZVYKROXRFLTLBVGPX32M46Q/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236405");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-asteval' package(s) announced via the openSUSE-SU-2025:0052-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-asteval fixes the following issues:

Update to 1.0.6:

 * drop testing and support for Python3.8, add Python 3.13,
 change document to reflect this.
 * implement safe_getattr and safe_format functions, fix bugs
 in UNSAFE_ATTRS and UNSAFE_ATTRS_DTYPES usage (boo#1236405,
 CVE-2025-24359)
 * make all procedure attributes private to curb access to AST
 nodes, which can be exploited
 * improvements to error messages, including use ast functions
 to construct better error messages
 * remove import of numpy.linalg, as documented
 * update doc description for security advisory

Update to 1.0.5:

 * more work on handling errors, including fixing #133 and
 adding more comprehensive tests for #129 and #132

Update to 1.0.4:

 * fix error handling that might result in null exception

Update to 1.0.3:

 * functions ('Procedures') defined within asteval have a `
 _signature()` method, now use in repr
 * add support for deleting subscript
 * nested symbol tables now have a Group() function
 * update coverage config
 * cleanups of exception handling : errors must now have an
 exception
 * several related fixes to suppress repeated exceptions: see GH
 #132 and #129
 * make non-boolean return values from comparison operators
 behave like Python - not immediately testing as bool

- update to 1.0.2:
 * fix NameError handling in expression code
 * make exception messages more Python-like
- update to 1.0.1:
 * security fixes, based on audit by Andrew Effenhauser, Ayman
 Hammad, and Daniel Crowley, IBM X-Force Security Research
 division
 * remove numpy modules polynomial, fft, linalg by default for
 security concerns
 * disallow string.format(), improve security of f-string
 evaluation

- update to 1.0.0:
 * fix (again) nested list comprehension (Issues #127 and #126).
 * add more testing of multiple list comprehensions.
 * more complete support for Numpy 2, and removal of many Numpy
 symbols that have been long deprecated.
 * remove AST nodes deprecated in Python 3.8.
 * clean up build files and outdated tests.
 * fixes to codecov configuration.
 * update docs.

- update to 0.9.33:
 * fixes for multiple list comprehensions (addressing #126)
 * add testing with optionally installed numpy_financial to CI
 * test existence of all numpy imports to better safeguard
 against missing functions (for safer numpy 2 transition)
 * update rendered doc to include PDF and zipped HTML

- update to 0.9.32:
 * add deprecations message for numpy functions to be removed in
 numpy 2.0
 * comparison operations use try/except for short-circuiting
 instead of checking for numpy arrays (addressing #123)
 * add Python 3.12 to testing
 * move repository from 'newville' to 'lmfit' organization
 * update doc theme, GitHub locations pointed to by docs, other
 doc tweaks.

- Update to 0.9.31:
 * cleanup numpy imports to avoid deprecated functions, add financial
 functions from numpy_financial ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-asteval' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python311-asteval", rpm:"python311-asteval~1.0.6~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
