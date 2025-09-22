# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1143.1");
  script_cve_id("CVE-2024-45337");
  script_tag(name:"creation_date", value:"2025-04-07 04:06:30 +0000 (Mon, 07 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1143-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1143-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251143-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239866");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038914.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-guest-agent' package(s) announced via the SUSE-SU-2025:1143-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for google-guest-agent fixes the following issues:

- CVE-2024-45337: golang.org/x/crypto/ssh: Fixed misuse of ServerConfig.PublicKeyCallback leading to authorization bypass (bsc#1234563).

Other fixes:
- Updated to version 20250327.01 (bsc#1239763, bsc#1239866)
 * Remove error messages from gce_workload_cert_refresh and
 metadata script runner (#527)
- from version 20250327.00
 * Update guest-logging-go dependency (#526)
 * Add 'created-by' metadata, and pass it as option to logging library (#508)
 * Revert 'oslogin: Correctly handle newlines at the end of
 modified files (#520)' (#523)
 * Re-enable disabled services if the core plugin was enabled (#522)
 * Enable guest services on package upgrade (#519)
 * oslogin: Correctly handle newlines at the end of modified files (#520)
 * Fix core plugin path (#518)
 * Fix package build issues (#517)
 * Fix dependencies ran go mod tidy -v (#515)
 * Fix debian build path (#514)
 * Bundle compat metadata script runner binary in package (#513)
 * Bump golang.org/x/net from 0.27.0 to 0.36.0 (#512)
 * Update startup/shutdown services to launch compat manager (#503)
 * Bundle new gce metadata script runner binary in agent package (#502)
 * Revert 'Revert bundling new binaries in the package (#509)' (#511)
- from version 20250326.00
 * Re-enable disabled services if the core plugin was enabled (#521)
- from version 20250324.00
 * Enable guest services on package upgrade (#519)
 * oslogin: Correctly handle newlines at the end of modified files (#520)
 * Fix core plugin path (#518)
 * Fix package build issues (#517)
 * Fix dependencies ran go mod tidy -v (#515)
 * Fix debian build path (#514)
 * Bundle compat metadata script runner binary in package (#513)
 * Bump golang.org/x/net from 0.27.0 to 0.36.0 (#512)
 * Update startup/shutdown services to launch compat manager (#503)
 * Bundle new gce metadata script runner binary in agent package (#502)
 * Revert 'Revert bundling new binaries in the package (#509)' (#511)
 * Revert bundling new binaries in the package (#509)
 * Fix typo in windows build script (#501)
 * Include core plugin binary for all packages (#500)
 * Start packaging compat manager (#498)
 * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
 * scripts: introduce a wrapper to locally build deb package (#490)
 * Introduce compat-manager systemd unit (#497)
- from version 20250317.00
 * Revert 'Revert bundling new binaries in the package (#509)' (#511)
 * Revert bundling new binaries in the package (#509)
 * Fix typo in windows build script (#501)
 * Include core plugin binary for all packages (#500)
 * Start packaging compat manager (#498)
 * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
 * scripts: introduce a wrapper to locally build deb package (#490)
 * Introduce compat-manager systemd unit (#497)
- from version 20250312.00
 * Revert bundling new binaries in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'google-guest-agent' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"google-guest-agent", rpm:"google-guest-agent~20250327.01~150000.1.60.1", rls:"openSUSELeap15.6"))) {
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
