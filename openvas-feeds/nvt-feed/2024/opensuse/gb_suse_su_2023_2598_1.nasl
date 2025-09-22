# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833640");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-41715", "CVE-2022-41723", "CVE-2022-46146");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:51 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:51 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for golang (SUSE-SU-2023:2598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2598-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JTLTPD7ERJRW2TGZZXR5OYS3URV5ZO7R");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang'
  package(s) announced via the SUSE-SU-2023:2598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-prometheus fixes the following issues:

  golang-github-prometheus-prometheus:

  * Security issues fixed in this version update to 2.37.6:

  * CVE-2022-46146: Fix basic authentication bypass vulnerability (bsc#1208049,
      jsc#PED-3576)

  * CVE-2022-41715: Update our regexp library to fix upstream (bsc#1204023)

  * CVE-2022-41723: Fixed go issue to avoid quadratic complexity in HPACK
      decoding (bsc#1208298)

  * Other non-security bugs fixed and changes in this version update to 2.37.6:

  * [BUGFIX] TSDB: Turn off isolation for Head compaction to fix a memory leak.

  * [BUGFIX] TSDB: Fix 'invalid magic number 0' error on Prometheus startup.

  * [BUGFIX] Agent: Fix validation of flag options and prevent WAL from growing
      more than desired.

  * [BUGFIX] Properly close file descriptor when logging unfinished queries.

  * [BUGFIX] TSDB: In the WAL watcher metrics, expose the type='exemplar' label
      instead of type='unknown' for exemplar records.

  * [BUGFIX] Alerting: Fix Alertmanager targets not being updated when alerts
      were queued.

  * [BUGFIX] Hetzner SD: Make authentication files relative to Prometheus config
      file.

  * [BUGFIX] Promtool: Fix promtool check config not erroring properly on
      failures.

  * [BUGFIX] Scrape: Keep relabeled scrape interval and timeout on reloads.

  * [BUGFIX] TSDB: Don't increment prometheus_tsdb_compactions_failed_total when
      context is canceled.

  * [BUGFIX] TSDB: Fix panic if series is not found when deleting series.

  * [BUGFIX] TSDB: Increase prometheus_tsdb_mmap_chunk_corruptions_total on out
      of sequence errors.

  * [BUGFIX] Uyuni SD: Make authentication files relative to Prometheus
      configuration file and fix default configuration values.

  * [BUGFIX] Fix serving of static assets like fonts and favicon.

  * [BUGFIX] promtool: Add --lint-fatal option.

  * [BUGFIX] Changing TotalQueryableSamples from int to int64.

  * [BUGFIX] tsdb/agent: Ignore duplicate exemplars.

  * [BUGFIX] TSDB: Fix chunk overflow appending samples at a variable rate.

  * [BUGFIX] Stop rule manager before TSDB is stopped.

  * [BUGFIX] Kubernetes SD: Explicitly include gcp auth from k8s.io.

  * [BUGFIX] Fix OpenMetrics parser to sort uppercase labels correctly.

  * [BUGFIX] UI: Fix scrape interval and duration tooltip not showing on target
      page.

  * [BUGFIX] Tracing/GRPC: Set TLS credentials only when insecure is false.

  * [BUGFIX] Agent: Fix ID collision when loading a WAL with multiple segments.

  * [BUGF ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'golang' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.37.6~150100.4.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.37.6~150100.4.17.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.37.6~150100.4.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.37.6~150100.4.17.1", rls:"openSUSELeap15.5"))) {
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