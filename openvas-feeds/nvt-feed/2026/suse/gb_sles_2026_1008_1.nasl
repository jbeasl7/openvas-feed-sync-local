# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1008.1");
  script_cve_id("CVE-2025-12816", "CVE-2025-13465", "CVE-2025-61140", "CVE-2026-1615", "CVE-2026-25547", "CVE-2026-27606");
  script_tag(name:"creation_date", value:"2026-03-27 04:49:18 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 16:05:11 +0000 (Wed, 25 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1008-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261008-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257897");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024921.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Prometheus ' package(s) announced via the SUSE-SU-2026:1008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Prometheus fixes the following issues:

golang-github-prometheus-alertmanager, golang-github-prometheus-node_exporter:

- Internal changes to fix build issues with no impact for customers

golang-github-prometheus-prometheus:

- Security issues fixed:

 * CVE-2026-27606: Fixed arbitrary file write via path traversal in rollup (bsc#1258893)
 * CVE-2026-25547: Fixed unbounded brace range expansion leading to excessive CPU and memory consumption (bsc#1257841)
 * CVE-2026-1615, CVE-2025-61140 The old web UI is no longer built due to security issues (bsc#1257897, bsc#1257442)
 * CVE-2025-13465: Bump lodash package to version 4.17.23 to fix prototype pollution vulnerability (bsc#1257329)
 * CVE-2025-12816: Interpretation conflict vulnerability allowing bypassing cryptographic verifications (bsc#1255588)

- Version update from 2.53.4 to 3.5.0 with the following highlighted changes (jsc#PED-13824):

 * Modernized Interface: Introduced a brand-new UI
 * Enhanced Cloud and Auth: Added unified AWS service discovery (EC2, ECS, Lightsail) and Azure Workload Identity support
 for more secure, native cloudauthentication.
 * Performance Standards: Fully integrated OpenTelemetry (OTLP) ingestion and moved Native Histograms from experimental
 to a stable feature.
 * Advanced Data Export: Rolled out Remote Write 2.0, offering better performance and metadata handling when sending
 data to external systems.
 * Query Power: Added new PromQL functions (like first_over_time and last_over_time) and optimization for grouping
 operations.
 * Better Visibility: The UI now displays detailed relabeling steps, scrape intervals, and timeouts, making it easier
 to troubleshoot why targets aren't reporting correctly.
 * Critical Fixes: Resolved significant memory leaks related to query logging and fixed bugs where targets were
 accidentally being scraped multiple times.");

  script_tag(name:"affected", value:"'Prometheus ' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.9.1~150100.3.38.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.9.1~150100.3.38.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.9.1~150100.3.38.1", rls:"SLES15.0SP6"))) {
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
