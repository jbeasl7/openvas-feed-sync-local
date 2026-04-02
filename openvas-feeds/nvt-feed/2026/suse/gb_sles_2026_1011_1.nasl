# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1011.1");
  script_cve_id("CVE-2025-1365");
  script_tag(name:"creation_date", value:"2026-03-27 04:49:18 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-04 20:07:34 +0000 (Tue, 04 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1011-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261011-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257941");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024919.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update 5.0.7 for Multi-Linux Manager Client Tools' package(s) announced via the SUSE-SU-2026:1011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-QubitProducts-exporter_exporter:

- Non-customer-facing optimization and update

golang-github-boynux-squid_exporter:

- Version update from 1.6.0 to 1.13.0 with the following highlighted changes and fixes (jsc#PED-14971):

 * Added compatibility for Squid 6 and support for the squid-internal-mgr metrics path.
 * Added TLS and Basic Authentication to the exporter's web interface.
 * Added support for the exporter to authenticate against the Squid proxy itself.
 * Allow the gathering of process information without requiring root privileges
 * The exporter can now be configured using environment variables
 * Added support for custom labels to all exported metrics for better data filtering.
 * New metrics to track if Squid is running (squid_up), how long a scrape takes, and if any errors occurred.
 * Added 'service time' metrics to analyze proxy speed and performance.
 * Added a metric for open file descriptors (process_open_fds) to help prevent connection bottlenecks.
 * Corrected the squid_client_http_requests_total metric to ensure accurate reporting.

golang-github-lusitaniae-apache_exporter:

- Version update from 1.0.8 to 1.0.10:

 * Updated github.com/prometheus/client_golang to 1.21.1
 * Updated github.com/prometheus/common to 0.63.0
 * Updated github.com/prometheus/exporter-toolkit to 0.14.0
 * Fixed signal handler logging
 * Migrated logging to log/slog

golang-github-prometheus-alertmanager:

- Non-customer-facing optimization and update

golang-github-prometheus-node_exporter:

- Non-customer-facing optimization and update

golang-github-prometheus-promu:

- Non-customer-facing optimization and update

spacecmd:

- Version 5.0.15-0
 * Fix typo in spacecmd help ca-cert flag (bsc#1253174)
 * Convert cached IDs to int (bsc#1251995)
 * Fix spacecmd binary file upload (bsc#1253659)

uyuni-tools:

- Version 0.1.38-0
 * Fix cobbler config migration to standalone files (bsc#1256803)
 * Detect custom apache and squid config in the /etc/uyuni/proxy
 folder
 * Add ssh tuning to configure sshd (bsc#1253738)
 * Ignore supportconfig errors (bsc#1255781)
 * Bump the default image tag to 5.0.7
 * Remove cgroup mount for podman containers (bsc#1253347)
 * Registry flag can be a string (bsc#1254589)
 * Use static supportconfig name to avoid dynamic search
 (bsc#1257941)");

  script_tag(name:"affected", value:"'Security update 5.0.7 for Multi-Linux Manager Client Tools' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.9.1~1.39.2", rls:"SLES12.0SP5"))) {
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
