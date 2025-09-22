# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856483");
  script_cve_id("CVE-2022-41715", "CVE-2022-41723", "CVE-2023-45142", "CVE-2024-6104");
  script_tag(name:"creation_date", value:"2024-09-18 04:01:27 +0000 (Wed, 18 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 18:27:50 +0000 (Wed, 18 Oct 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3288-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243288-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228556");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019440.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-prometheus' package(s) announced via the SUSE-SU-2024:3288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-prometheus fixes the following issues:

- Require Go > 1.20 for building

- Bump go-retryablehttp to version 0.7.7
 (CVE-2024-6104, bsc#1227038)
- Migrate from `disabled` to `manual` service mode
- Add0003-Bump-go-retryablehttp.patch
- Update to 2.45.6 (jsc#PED-3577):
 * Security fixes in dependencies
- Update to 2.45.5:
 * [BUGFIX] tsdb/agent: ensure that new series get written to WAL
 on rollback.
 * [BUGFIX] Remote write: Avoid a race condition when applying
 configuration.
- Update to 2.45.4:
 * [BUGFIX] Remote read: Release querier resources before encoding
 the results.
- Update to 2.45.3:
 * Security fixes in dependencies
 * [BUGFIX] TSDB: Remove double memory snapshot on shutdown.
- Update to 2.45.2:
 * Security fixes in dependencies
 * [SECURITY] Updated otelhttp to version 0.46.1
 (CVE-2023-45142, bsc#1228556)
 * [BUGFIX] TSDB: Fix PostingsForMatchers race with creating new
 series.
- Update to 2.45.1:
 * [ENHANCEMENT] Hetzner SD: Support larger ID's that will be used
 by Hetzner in September.
 * [BUGFIX] Linode SD: Cast InstanceSpec values to int64 to avoid
 overflows on 386 architecture.
 * [BUGFIX] TSDB: Handle TOC parsing failures.

- update to 2.45.0 (jsc#PED-5406):
 * [FEATURE] API: New limit parameter to limit the number of items
 returned by `/api/v1/status/tsdb` endpoint.
 * [FEATURE] Config: Add limits to global config.
 * [FEATURE] Consul SD: Added support for `path_prefix`.
 * [FEATURE] Native histograms: Add option to scrape both classic
 and native histograms.
 * [FEATURE] Native histograms: Added support for two more
 arithmetic operators `avg_over_time` and `sum_over_time`.
 * [FEATURE] Promtool: When providing the block id, only one block
 will be loaded and analyzed.
 * [FEATURE] Remote-write: New Azure ad configuration to support
 remote writing directly to Azure Monitor workspace.
 * [FEATURE] TSDB: Samples per chunk are now configurable with
 flag `storage.tsdb.samples-per-chunk`. By default set to its
 former value 120.
 * [ENHANCEMENT] Native histograms: bucket size can now be limited
 to avoid scrape fails.
 * [ENHANCEMENT] TSDB: Dropped series are now deleted from the WAL
 sooner.
 * [BUGFIX] Native histograms: ChunkSeries iterator now checks if
 a new sample can be appended to the open chunk.
 * [BUGFIX] Native histograms: Fix Histogram Appender
 `Appendable()` segfault.
 * [BUGFIX] Native histograms: Fix setting reset header to gauge
 histograms in seriesToChunkEncoder.
 * [BUGFIX] TSDB: Tombstone intervals are not modified after Get()
 call.
 * [BUGFIX] TSDB: Use path/filepath to set the WAL directory.
- update to 2.44.0:
 * [FEATURE] Remote-read: Handle native histograms.
 * [FEATURE] Promtool: Health and readiness check of prometheus
 server in CLI.
 * [FEATURE] PromQL: Add `query_samples_total` metric, the total
 number of samples loaded by all queries.
 * [ENHANCEMENT] Storage: Optimise ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'golang-github-prometheus-prometheus' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.45.6~150100.4.20.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"firewalld-prometheus-config", rpm:"firewalld-prometheus-config~0.1~150100.4.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~2.45.6~150100.4.20.1", rls:"openSUSELeap15.6"))) {
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
