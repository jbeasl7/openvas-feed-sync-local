# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01989.1");
  script_cve_id("CVE-2023-45288", "CVE-2024-9264", "CVE-2024-9476", "CVE-2025-22870", "CVE-2025-22872", "CVE-2025-2703", "CVE-2025-29923", "CVE-2025-3454", "CVE-2025-3580", "CVE-2025-4123");
  script_tag(name:"creation_date", value:"2025-06-20 04:11:07 +0000 (Fri, 20 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-01 18:14:31 +0000 (Fri, 01 Nov 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01989-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501989-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243714");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-0/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-1/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-2/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-3/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-4/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v11-5/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040349.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Multi-Linux Manager Client Tools' package(s) announced via the SUSE-SU-2025:01989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-prometheus-prometheus was updated to version 2.53.4:

- Security issues fixed:
 * CVE-2023-45288: Require Go >= 1.23 for building (bsc#1236516)
 * CVE-2025-22870: Bumped golang.org/x/net to version 0.39.0 (bsc#1238686)

- Other bugs fixes from version 2.53.4:
 * Runtime: fixed GOGC being set to 0 when installed
 with empty prometheus.yml file resulting high cpu usage
 * Scrape: fixed dropping valid metrics after previous
 scrape failed

prometheus-blackbox_exporter was updated from version 0.24.0 to 0.26.0 (jsc#PED-12872):

- Security issues fixed:
 * CVE-2025-22870: Fixed proxy bypassing using IPv6 zone IDs (bsc#1238680)
 * CVE-2023-45288: Fixed closing connections when receiving too many headers (bsc#1236515)

- Other changes from version 0.26.0:
 * Changes:
 + Replace go-kit/log with log/slog module.
 * Features:
 + Add metric to record tls ciphersuite negotiated during
 handshake.
 + Add a way to export labels with content matched by the probe.
 Reports Certificate Serial number.
 * Enhancement:
 + Add stale workflow to start sync with stale.yaml in Prometheus.
 * Bug fixes:
 + Only register grpc TLS metrics on successful handshake.

- Other changes from version 0.25.0:
 * Features:
 + Allow to get Probe logs by target.
 + Log errors from probe.
 * Bug fixes:
 + Prevent logging confusing error message.
 + Explicit registration of internal exporter metrics.

grafana was updated from version 10.4.15 to 11.5.5 (jsc#PED-12918):

- Security issues fixed:
 * CVE-2025-4123: Fix cross-site scripting vulnerability (bsc#1243714).
 * CVE-2025-22872: Bump golang.org/x/net/html (bsc#1241809)
 * CVE-2025-3580: Prevent unauthorized server admin deletion (bsc#1243672).
 * CVE-2025-29923: Bump github.com/redis/go-redis/v9 to 9.6.3.
 * CVE-2025-3454: Sanitize paths before evaluating access to route (bsc#1241683).
 * CVE-2025-2703: Fix built-in XY Chart plugin (bsc#1241687).
 * CVE-2025-22870: Bump golang.org/x/net (bsc#1238703).
 * CVE-2024-9476: Fix Migration Assistant issue (bsc#1233343)
 * CVE-2024-9264: SQL Expressions (bsc#1231844)
 * CVE-2023-45288: Bump golang.org/x/net (bsc#1236510)
 * CVE-2025-22870: Bump golang.org/x/net to version 0.37.0 (bsc#1238686)

- Potential breaking changes in version 11.5.0:
 * Loki: Default to /labels API with query param instead of /series API.

- Potential breaking changes in version 11.0.1:
 * If you had selected your language as 'Portugues Brasileiro'
 previously, this will be reset. You have to select it again in
 your Preferences for the fix to be applied and the translations
 will then be shown.

- Potential breaking changes in version 11.0.0:
 * AngularJS support is turned off by default.
 * Legacy alerting is entirely removed.
 * Subfolders cause very rare issues with folders which have
 slashes in their names.
 * The input data source is removed.
 * Data sources: Responses which are ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Multi-Linux Manager Client Tools' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.26.0~150000.1.27.1", rls:"openSUSELeap15.6"))) {
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
