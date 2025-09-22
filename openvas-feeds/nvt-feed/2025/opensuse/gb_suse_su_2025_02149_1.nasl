# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02149.1");
  script_cve_id("CVE-2024-45339");
  script_tag(name:"creation_date", value:"2025-06-30 04:14:41 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02149-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502149-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244503");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-osconfig-agent' package(s) announced via the SUSE-SU-2025:02149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for google-osconfig-agent fixes the following issues:

- Update to version 20250416.02 (bsc#1244304, bsc#1244503)
 * defaultSleeper: tolerate 10% difference to reduce test flakiness
 * Add output of some packagemanagers to the testdata
- from version 20250416.01
 * Refactor OS Info package
- from version 20250416.00
 * Report RPM inventory as YUM instead of empty SoftwarePackage
 when neither Zypper nor YUM are installed.
- from version 20250414.00
 * Update hash computation algorithm
- Update to version 20250320.00
 * Bump github.com/envoyproxy/protoc-gen-validate from 1.1.0 to 1.2.1
- from version 20250318.00
 * Bump go.opentelemetry.io/otel/sdk/metric from 1.32.0 to 1.35.0
- from version 20250317.02
 * Bump cel.dev/expr from 0.18.0 to 0.22.0
 * Bump github.com/golang/glog from 1.2.3 to 1.2.4 in the go_modules group
- from version 20250317.01
 * Bump cloud.google.com/go/logging from 1.12.0 to 1.13.0
- from version 20250317.00
 * Add tests for retryutil package.
- from version 20250306.00
 * Update OWNERS
- from version 20250206.01
 * Use separate counters for pre- and post-patch reboots.
- from version 20250206.00
 * Update owners
- from version 20250203.00
 * Fix the vet errors for contants in logging
- from version 20250122.00
 * change available package check
- from version 20250121.00
 * Fix Inventory reporting e2e tests.
- from version 20250120.00
 * fix e2e tests
- Add -buildmode=pie to go build command line (bsc#1239948)
- merged upstream
- Renumber patches");

  script_tag(name:"affected", value:"'google-osconfig-agent' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"google-osconfig-agent", rpm:"google-osconfig-agent~20250416.02~150000.1.50.1", rls:"openSUSELeap15.6"))) {
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
