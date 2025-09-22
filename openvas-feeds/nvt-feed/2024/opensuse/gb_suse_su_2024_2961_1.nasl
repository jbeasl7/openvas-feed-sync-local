# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856380");
  script_cve_id("CVE-2024-22034");
  script_tag(name:"creation_date", value:"2024-08-20 04:12:13 +0000 (Tue, 20 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2961-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242961-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225911");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036632.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'osc' package(s) announced via the SUSE-SU-2024:2961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for osc fixes the following issues:

- 1.9.0
 - Security:
 - Fix possibility to overwrite special files in .osc (CVE-2024-22034 bsc#1225911)
 Source files are now stored in the 'sources' subdirectory which prevents
 name collisons. This requires changing version of '.osc' store to 2.0.
 - Command-line:
 - Introduce build --checks parameter
 - Library:
 - OscConfigParser: Remove automatic __name__ option

- 1.8.3
 - Command-line:
 - Change 'repairwc' command to always run all repair steps
 - Library:
 - Make most of the fields in KeyinfoPubkey and KeyinfoSslcert models optional
 - Fix colorize() to avoid wrapping empty string into color escape sequences
 - Provide default values for kwargs.get/pop in get_results() function

- 1.8.2
 - Library:
 - Change 'repairwc' command to fix missing .osc/_osclib_version
 - Make error message in check_store_version() more generic to work for both projects and packages
 - Fix check_store_version in project store

- 1.8.1
 - Command-line:
 - Fix 'linkpac' command crash when used with '--disable-build' or '--disable-publish' option

- 1.8.0
 - Command-line:
 - Improve 'submitrequest' command to inherit description from superseded request
 - Fix 'mv' command when renaming a file multiple times
 - Improve 'info' command to support projects
 - Improve 'getbinaries' command by accepting '-M' / '--multibuild-package' option outside checkouts
 - Add architecture filtering to 'release' command
 - Change 'results' command so the normal and multibuild packages have the same output
 - Change 'results' command to use csv writer instead of formatting csv as string
 - Add couple mutually exclusive options errors to 'results' command
 - Set a default value for 'results --format' only for the csv output
 - Add support for 'results --format' for the default text mode
 - Update help text for '--format' option in 'results' command
 - Add 'results --fail-on-error/-F' flag
 - Redirect venv warnings from stderr to debug output
 - Configuration:
 - Fix config parser to throw an exception on duplicate sections or options
 - Modify conf.get_config() to print permissions warning to stderr rather than stdout
 - Library:
 - Run check_store_version() in obs_scm.Store and fix related code in Project and Package
 - Forbid extracting files with absolute path from 'cpio' archives (bsc#1122683)
 - Forbid extracting files with absolute path from 'ar' archives (bsc#1122683)
 - Remove no longer valid warning from core.unpack_srcrpm()
 - Make obs_api.KeyinfoSslcert keyid and fingerprint fields optional
 - Fix return value in build build.create_build_descr_data()
 - Fix core.get_package_results() to obey 'multibuild_packages' argument
 - Tests:
 - Fix tests so they don't modify fixtures

- 1.7.0
 - Command-line:
 - Add 'person search' command
 - Add 'person register' command
 - Add '-M/--multibuild-package' option to '[what]dependson' commands
 - Update ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'osc' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"osc", rpm:"osc~1.9.0~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"osc", rpm:"osc~1.9.0~150400.10.6.1", rls:"openSUSELeap15.6"))) {
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
