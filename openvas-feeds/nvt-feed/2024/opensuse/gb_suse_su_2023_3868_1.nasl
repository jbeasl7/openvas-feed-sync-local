# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833367");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-32149", "CVE-2022-41723", "CVE-2022-46146", "CVE-2023-29409");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:51 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager Client Tools (SUSE-SU-2023:3868-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3868-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UQ7HS3VCKOT5E2DFL3B52L55ZRUPQPA4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools'
  package(s) announced via the SUSE-SU-2023:3868-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  golang-github-lusitaniae-apache_exporter:

  * Security issues fixed:

  * CVE-2022-32149: Fix denial of service vulnerability (bsc#1204501)

  * CVE-2022-41723: Fix uncontrolled resource consumption (bsc#1208270)

  * CVE-2022-46146: Fix authentication bypass vulnerability (bsc#1208046)

  * Changes and bugs fixed:

  * Updated to 1.0.0 (jsc#PED-5405)

  * Improved flag parsing

  * Added support for custom headers

  * Changes from 0.13.1

  * Fix panic caused by missing flagConfig options

  * Added AppArmor profile

  * Added sandboxing options to systemd service unit

  * Build using promu

  * Build with Go 1.19

  * Exclude s390 architecture

  golang-github-prometheus-prometheus:

  * This update introduces breaking changes. Please, read carefully the provided
      information.

  * Security issues fixed:

  * CVE-2022-41723: Fix uncontrolled resource consumption by updating Go to
      version 1.20.1 (bsc#1208298)

  * Updated to 2.45.0 (jsc#PED-5406):

  * [FEATURE] API: New limit parameter to limit the number of items returned by
      `/api/v1/status/tsdb` endpoint

  * [FEATURE] Config: Add limits to global config

  * [FEATURE] Consul SD: Added support for `path_prefix`

  * [FEATURE] Native histograms: Add option to scrape both classic and native
      histograms.

  * [FEATURE] Native histograms: Added support for two more arithmetic operators
      `avg_over_time` and `sum_over_time`

  * [FEATURE] Promtool: When providing the block id, only one block will be
      loaded and analyzed

  * [FEATURE] Remote-write: New Azure ad configuration to support remote writing
      directly to Azure Monitor workspace

  * [FEATURE] TSDB: Samples per chunk are now configurable with flag
      `storage.tsdb.samples-per-chunk`. By default set to its former value 120

  * [ENHANCEMENT] Native histograms: bucket size can now be limited to avoid
      scrape fails

  * [ENHANCEMENT] TSDB: Dropped series are now deleted from the WAL sooner

  * [BUGFIX] Native histograms: ChunkSeries iterator now checks if a new sample
      can be appended to the open chunk

  * [BUGFIX] Native histograms: Fix Histogram Appender `Appendable()` segfault

  * [BUGFIX] Native histograms: Fix setting reset header to gauge histograms in
      seriesToChunkEncoder

  * [BUGFIX] TSDB: Tombstone intervals are not modified after Get() call

  * [BUGFIX] TSDB: Use path/filepath to set the WAL directory.

  * Changes from 2.44.0:

  * [FEATURE] Remote-read: Handle native histograms
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.18.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.0~150000.1.17.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.1~150000.1.14.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter-debuginfo", rpm:"golang-github-lusitaniae-apache_exporter-debuginfo~1.0.0~150000.1.17.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.23.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.3.3~150000.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.23~150000.3.104.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.18.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.0~150000.1.17.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.1~150000.1.14.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter-debuginfo", rpm:"golang-github-lusitaniae-apache_exporter-debuginfo~1.0.0~150000.1.17.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.23.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.3.3~150000.3.21.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.23~150000.3.104.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.18.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.0~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.1~150000.1.14.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter-debuginfo", rpm:"golang-github-lusitaniae-apache_exporter-debuginfo~1.0.0~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.23.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.3.3~150000.3.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.23~150000.3.104.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.18.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.0~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.1~150000.1.14.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter-debuginfo", rpm:"golang-github-lusitaniae-apache_exporter-debuginfo~1.0.0~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.24.0~150000.1.23.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.3.3~150000.3.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.23~150000.3.104.2", rls:"openSUSELeap15.5"))) {
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