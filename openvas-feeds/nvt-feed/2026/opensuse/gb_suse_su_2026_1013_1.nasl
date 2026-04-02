# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1013.1");
  script_cve_id("CVE-2025-12816", "CVE-2025-13465", "CVE-2025-3415", "CVE-2025-61140", "CVE-2025-68156", "CVE-2026-1615", "CVE-2026-21720", "CVE-2026-21721", "CVE-2026-21722", "CVE-2026-25547", "CVE-2026-27606");
  script_tag(name:"creation_date", value:"2026-03-27 04:48:51 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 16:05:11 +0000 (Wed, 25 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1013-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261013-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258893");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024917.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update 5.0.7 for Multi-Linux Manager Client Tools' package(s) announced via the SUSE-SU-2026:1013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

dracut-saltboot:

- Version update to 1.1.0:

 * Retry DHCP requests up to 3 times (bsc#1253004)

golang-github-QubitProducts-exporter_exporter:

- Non-customer-facing optimization and update

golang-github-boynux-squid_exporter:

- Version update from 1.6.0 to 1.13.0 with the following highlighted changes and fixes (jsc#PED-14971):

 * Added compatibility for Squid 6 and support for the squid-internal-mgr metrics path
 * Added TLS and Basic Authentication to the exporter's web interface
 * Added support for the exporter to authenticate against the Squid proxy itself
 * Allow the gathering of process information without requiring root privileges
 * The exporter can now be configured using environment variables
 * Added support for custom labels to all exported metrics for better data filtering
 * New metrics to track if Squid is running (squid_up), how long a scrape takes, and if any errors occurred
 * Added 'service time' metrics to analyze proxy speed and performance.
 * Added a metric for open file descriptors (process_open_fds) to help prevent connection bottlenecks
 * Corrected the squid_client_http_requests_total metric to ensure accurate reporting


golang-github-lusitaniae-apache_exporter:

- Version update from 1.0.8 to 1.0.10:

 * Updated github.com/prometheus/client_golang to 1.21.1
 * Updated github.com/prometheus/common to 0.63.0
 * Updated github.com/prometheus/exporter-toolkit to 0.14.0
 * Fixed signal handler logging

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
 operations
 * Better Visibility: The UI now displays detailed relabeling steps, scrape ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Security update 5.0.7 for Multi-Linux Manager Client Tools' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~1.1.0~150000.1.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-boynux-squid_exporter", rpm:"golang-github-boynux-squid_exporter~1.13.0~150000.1.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.10~150000.1.26.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-promu", rpm:"golang-github-prometheus-promu~0.17.0~150000.3.30.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.26.0~150000.1.30.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.15~150000.3.142.1", rls:"openSUSELeap15.6"))) {
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
