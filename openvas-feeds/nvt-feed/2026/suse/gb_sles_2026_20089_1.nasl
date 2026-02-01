# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20089.1");
  script_cve_id("CVE-2025-47911", "CVE-2025-47913", "CVE-2025-58190");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:52 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20089-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620089-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253609");
  script_xref(name:"URL", value:"https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.139.0/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/open-telemetry/opentelemetry-collector/blob/v0.139.0/CHANGELOG.md");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023811.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'alloy' package(s) announced via the SUSE-SU-2026:20089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for alloy fixes the following issues:

Upgrade to version 1.12.1.


Security issues fixed:

- CVE-2025-47911: golang.org/x/net/html: quadratic complexity algorithms used when parsing untrusted HTML documents
 (bsc#1251509).
- CVE-2025-58190: golang.org/x/net/html: excessive memory consumption by `html.ParseFragment` when processing specially
 crafted input (bsc#1251716).
- CVE-2025-47913: golang.org/x/crypto: early client process termination when receiving an unexpected message type in
 response to a key listing or signing request (bsc#1253609).

Other updates and bugfixes:

- Version 1.12.1:
 * Bugfixes
 - update to Beyla 2.7.10.

- Version 1.12.0:
 * Breaking changes
 - `prometheus.exporter.blackbox`, `prometheus.exporter.snmp` and `prometheus.exporter.statsd` now use the component
 ID instead of the hostname as their instance label in their exported metrics.
 * Features
 - (Experimental) Add an `otelcol.receiver.cloudflare` component to receive logs pushed by Cloudflare's LogPush
 jobs.
 - (Experimental) Additions to experimental `database_observability.mysql` component:
 - `explain_plans`
 - collector now changes schema before returning the connection to the pool.
 - collector now passes queries more permissively.
 - enable `explain_plans` collector by default
 - (Experimental) Additions to experimental `database_observability.postgres` component:
 - `explain_plans`
 - added the explain plan collector.
 - collector now passes queries more permissively.
 - `query_samples`
 - add user field to wait events within `query_samples` collector.
 - rework the query samples collector to buffer per-query execution state across scrapes and emit finalized
 entries.
 - process turned idle rows to calculate finalization times precisely and emit first seen idle rows.
 - `query_details`
 - escape queries coming from `pg_stat_statements` with quotes.
 - enable `explain_plans` collector by default.
 - safely generate `server_id` when UDP socket used for database connection.
 - add table registry and include 'validated' in parsed table name logs.
 - Add `otelcol.exporter.googlecloudpubsub` community component to export metrics, traces, and logs to Google Cloud
 Pub/Sub topic.
 - Add `structured_metadata_drop` stage for `loki.process` to filter structured metadata.
 - Send remote config status to the remote server for the `remotecfg` service.
 - Send effective config to the remote server for the `remotecfg` service.
 - Add a `stat_statements` configuration block to the `prometheus.exporter.postgres` component to enable selecting
 both the query ID and the full SQL statement. The new block includes one option to enable statement selection,
 and another to configure the maximum length of the statement text.
 - Add truncate stage for `loki.process` to truncate log entries, label values, and `structured_metadata` values.
 - Add `u_probe_links` & `load_probe` configuration fields ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'alloy' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"alloy", rpm:"alloy~1.12.1~160000.1.1", rls:"SLES16.0.0"))) {
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
