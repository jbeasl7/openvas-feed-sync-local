# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3737.1");
  script_cve_id("CVE-2019-20916");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-16 14:40:34 +0000 (Wed, 16 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3737-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3737-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203737-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip, python-scripttest' package(s) announced via the SUSE-SU-2020:3737-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-pip, python-scripttest fixes the following issues:

Update in SLE-15 (bsc#1175297, jsc#ECO-3035, jsc#PM-2318)

python-pip was updated to 20.0.2:

Fix a regression in generation of compatibility tags

Rename an internal module, to avoid ImportErrors due to improper
 uninstallation

Switch to a dedicated CLI tool for vendoring dependencies.

Remove wheel tag calculation from pip and use packaging.tags. This
 should provide more tags ordered better than in prior releases.

 Deprecate setup.py-based builds that do not generate an .egg-info
 directory.

 The pip>=20 wheel cache is not retro-compatible with previous versions.
 Until pip 21.0, pip will continue to take advantage of existing legacy
 cache entries.

 Deprecate undocumented --skip-requirements-regex option.

 Deprecate passing install-location-related options via --install-option.

 Use literal 'abi3' for wheel tag on CPython 3.x, to align with PEP 384
 which only defines it for this platform.

 Remove interpreter-specific major version tag e.g. cp3-none-any from
 consideration. This behavior was not documented strictly, and this tag
 in particular is not useful. Anyone with a use case can create an issue
 with pypa/packaging.

 Wheel processing no longer permits wheels containing more than one
 top-level .dist-info directory.

 Support for the git+git@ form of VCS requirement is being deprecated
 and will be removed in pip 21.0. Switch to git+https:// or git+ssh://.
 git+git:// also works but its use is discouraged as it is insecure.

 Default to doing a user install (as if --user was passed) when the main
 site-packages directory is not writeable and user site-packages are
 enabled.

 Warn if a path in PATH starts with tilde during pip install.

 Cache wheels built from Git requirements that are considered immutable,
 because they point to a commit hash.

 Add option --no-python-version-warning to silence warnings related to
 deprecation of Python versions.

 Cache wheels that pip wheel built locally, matching what pip install
 does. This particularly helps performance in workflows where pip wheel
 is used for building before installing. Users desiring the original
 behavior can use pip wheel --no-cache-dir

 Display CA information in pip debug.

 Show only the filename (instead of full URL), when downloading from
 PyPI.

 Suggest a more robust command to upgrade pip itself to avoid confusion
 when the current pip command is not available as pip.

 Define all old pip console script entrypoints to prevent import issues
 in stale wrapper scripts.

 The build step of pip wheel now builds all wheels to a cache first,
 then copies them to the wheel directory all at once. Before, it built
 them to a temporary directory and moved them to the wheel directory one
 by one.

 Expand ~ prefix to user directory in path options, configs, and
 environment variables. Values that may be either URL or path ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-pip, python-scripttest' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Python2 15-SP1, SUSE Linux Enterprise Module for Python2 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~20.0.2~6.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pip", rpm:"python2-pip~20.0.2~6.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~20.0.2~6.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pip", rpm:"python2-pip~20.0.2~6.12.1", rls:"SLES15.0SP2"))) {
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
