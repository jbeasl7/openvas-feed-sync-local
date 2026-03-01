# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20232.1");
  script_cve_id("CVE-2025-12816", "CVE-2025-13465");
  script_tag(name:"creation_date", value:"2026-02-13 04:41:11 +0000 (Fri, 13 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 17:10:07 +0000 (Tue, 17 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20232-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20232-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620232-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257329");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024095.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-prometheus' package(s) announced via the SUSE-SU-2026:20232-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-prometheus fixes the following issues:

Update to version 3.5.0:

Security issues fixed:

- CVE-2025-13465: prototype pollution in the _.unset and _.omit functions can lead to deletion of methods from global (bsc#1257329).
- CVE-2025-12816: interpretation conflict vulnerability allowing bypassing cryptographic verifications (bsc#1255588).

Other updates and bugfixes:

- Update to 3.5.0 (jsc#PED-13824):

 * [FEATURE] Remote-write: Add support for Azure Workload Identity
 as an authentication method for the receiver.
 * [FEATURE] PromQL: Add first_over_time(...) and
 ts_of_first_over_time(...) behind feature flag.
 * [FEATURE] Federation: Add support for native histograms with
 custom buckets (NHCB).
 * [ENHANCEMENT] PromQL: Add warn-level annotations for counter
 reset conflicts in certain histogram operations.
 * [ENHANCEMENT] UI: Add scrape interval and scrape timeout to
 targets page.

- Update to 3.4.0:

 * Add unified AWS service discovery for ec2, lightsail and ecs services.
 * [FEATURE] Native histograms are now a stable, but optional
 feature.
 * [FEATURE] UI: Show detailed relabeling steps for each
 discovered target.
 * [ENHANCEMENT] Alerting: Add 'unknown' state for alerting rules
 that haven't been evaluated yet.
 * [BUGFIX] Scrape: Fix a bug where scrape cache would not be
 cleared on startup.

- Update to 3.3.0:

 * [FEATURE] Spring Boot 3.3 includes support for the Prometheus
 Client 1.x.
 * [ENHANCEMENT] Dependency management for Dropwizard Metrics has
 been removed.

- Update to 3.2.0:

 * [FEATURE] OAuth2: support jwt-bearer grant-type (RFC7523 3.1).
 * [ENHANCEMENT] PromQL: Reconcile mismatched NHCB bounds in Add
 and Sub.
 * [BUGFIX] TSDB: Native Histogram Custom Bounds with a NaN
 threshold are now rejected.

- Update to 3.1.0:

 * [FEATURE] Remote-write 2 (receiving): Update to 2.0-rc.4 spec.
 'created timestamp' (CT) is now called 'start timestamp' (ST).
 * [BUGFIX] Mixin: Add static UID to the remote-write dashboard.

- Update to 3.0.1:

 * [BUGFIX] Promql: Make subqueries left open.
 * [BUGFIX] Fix memory leak when query log is enabled.
 * [BUGFIX] Support utf8 names on /v1/label/:name/values endpoint.

- Update to 3.0.0:

 * [CHANGE] Deprecated feature flags removed.
 * [FEATURE] New UI.
 * [FEATURE] Remote Write 2.0.
 * [FEATURE] OpenTelemetry Support.
 * [FEATURE] UTF-8 support is now stable and enabled by default.
 * [FEATURE] OTLP Ingestion.
 * [FEATURE] Native Histograms.
 * [BUGFIX] PromQL: Fix count_values for histograms.
 * [BUGFIX] TSDB: Fix race on stale values in headAppender.
 * [BUGFIX] UI: Fix selector / series formatting for empty metric
 names.

- Update to 2.55.0:

 * [FEATURE] PromQL: Add `last_over_time` function.
 * [FEATURE] Agent: Add `prometheus_agent_build_info` metric.
 * [ENHANCEMENT] PromQL: Optimise `group()` and `group by()`.
 * [ENHANCEMENT] TSDB: Reduce memory usage when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'golang-github-prometheus-prometheus' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-prometheus", rpm:"golang-github-prometheus-prometheus~3.5.0~160000.1.1", rls:"SLES16.0.0"))) {
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
