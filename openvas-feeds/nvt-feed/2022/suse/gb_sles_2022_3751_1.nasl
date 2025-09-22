# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3751.1");
  script_cve_id("CVE-2022-31097", "CVE-2022-31107");
  script_tag(name:"creation_date", value:"2022-10-27 04:38:58 +0000 (Thu, 27 Oct 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-23 14:24:29 +0000 (Wed, 23 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3751-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3751-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223751-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201539");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012706.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2022:3751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

dracut-saltboot:

- Update to version 0.1.1661440542.6cbe0da
 * Use standard susemanager.conf
 * Move image services to dracut-saltboot package
 * Use salt bundle

golang-github-lusitaniae-apache_exporter:

- Update to upstream release 0.11.0 (jsc#SLE-24791)
 * Add TLS support
 * Switch to logger, please check --log.level and --log.format
 flags
- Update to version 0.10.1
 * Bugfix: Reset ProxyBalancer metrics on each scrape to
 remove stale data
- Update to version 0.10.0
 * Add Apache Proxy and other metrics
- Update to version 0.8.0
 * Change commandline flags
 * Add metrics: Apache version, request duration total
- Adapted to build on Enterprise Linux 8
- Require building with Go 1.15
- Add %license macro for LICENSE file

grafana:

- Update to version 8.3.10
 + Security:
 * CVE-2022-31097: Cross Site Scripting vulnerability in the Unified Alerting (bsc#1201535)
 * CVE-2022-31107: Fixes OAuth account takeover vulnerability (bsc#1201539)
- Update to version 8.3.9
 + Bug fixes:
 * Geomap: Display legend
 * Prometheus: Fix timestamp truncation
- Update to version 8.3.7
 + Bug fix:
 * Provisioning: Ensure that the default value for orgID is set
 when provisioning datasources to be deleted.
- Update to version 8.3.6
 + Features and enhancements:
 * Cloud Monitoring: Reduce request size when listing labels.
 * Explore: Show scalar data result in a table instead of graph.
 * Snapshots: Updates the default external snapshot server URL.
 * Table: Makes footer not overlap table content.
 * Tempo: Add request histogram to service graph datalink.
 * Tempo: Add time range to tempo search query behind a feature flag.
 * Tempo: Auto-clear results when changing query type.
 * Tempo: Display start time in search results as relative time.
 * CloudMonitoring: Fix resource labels in query editor.
 * Cursor sync: Apply the settings without saving the dashboard.
 * LibraryPanels: Fix for Error while cleaning library panels.
 * Logs Panel: Fix timestamp parsing for string dates without timezone.
 * Prometheus: Fix some of the alerting queries that use reduce/math operation.
 * TablePanel: Fix ad-hoc variables not working on default datasources.
 * Text Panel: Fix alignment of elements.
 * Variables: Fix for constant variables in self referencing links.
- Update to version 8.3.5 (jsc#SLE-23439, jsc#SLE-23422, jsc#SLE-24565)

mgr-daemon:

- Version 4.3.6-1
 * Update translation strings

spacecmd:

- Version 4.3.15-1
 * Process date values in spacecmd api calls (bsc#1198903)

spacewalk-client-tools:

- Version 4.3.12-1
 * Update translation strings

uyuni-common-libs:

- Version 4.3.6-1
 * Do not allow creating path if nonexistent user or group in fileutils.");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150000.3.18.1", rls:"SLES15.0"))) {
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
