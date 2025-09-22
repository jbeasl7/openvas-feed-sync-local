# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1970.1");
  script_cve_id("CVE-2019-10215", "CVE-2019-15043", "CVE-2020-12245", "CVE-2020-13379");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-16 17:49:58 +0000 (Tue, 16 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1970-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1970-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201970-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172462");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007159.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2020:1970-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

cobbler:

- Calculate relative path for kernel and inited when generating
 grub entry (bsc#1170231)
 Added: fix-grub2-entry-paths.diff
- Fix os-release version detection for SUSE
 Modified: sles15.patch
- Jinja2 template library fix (bsc#1141661)
- Removes string replace for textmode fix (bsc#1134195)

golang-github-prometheus-node_exporter:

- Update to 0.18.1
 * [BUGFIX] Fix incorrect sysctl call in BSD meminfo collector, resulting in broken swap metrics on FreeBSD #1345
 * [BUGFIX] Fix rollover bug in mountstats collector #1364
 * Renamed interface label to device in netclass collector for consistency with
 * other network metrics #1224
 * The cpufreq metrics now separate the cpufreq and scaling data based on what the driver provides. #1248
 * The labels for the network_up metric have changed, see issue #1236
 * Bonding collector now uses mii_status instead of operstatus #1124
 * Several systemd metrics have been turned off by default to improve performance #1254
 * These include unit_tasks_current, unit_tasks_max, service_restart_total, and unit_start_time_seconds
 * The systemd collector blacklist now includes automount, device, mount, and slice units by default. #1255
 * [CHANGE] Bonding state uses mii_status #1124
 * [CHANGE] Add a limit to the number of in-flight requests #1166
 * [CHANGE] Renamed interface label to device in netclass collector #1224
 * [CHANGE] Add separate cpufreq and scaling metrics #1248
 * [CHANGE] Several systemd metrics have been turned off by default to improve performance #1254
 * [CHANGE] Expand systemd collector blacklist #1255
 * [CHANGE] Split cpufreq metrics into a separate collector #1253
 * [FEATURE] Add a flag to disable exporter metrics #1148
 * [FEATURE] Add kstat-based Solaris metrics for boottime, cpu and zfs collectors #1197
 * [FEATURE] Add uname collector for FreeBSD #1239
 * [FEATURE] Add diskstats collector for OpenBSD #1250
 * [FEATURE] Add pressure collector exposing pressure stall information for Linux #1174
 * [FEATURE] Add perf exporter for Linux #1274
 * [ENHANCEMENT] Add Infiniband counters #1120
 * [ENHANCEMENT] Add TCPSynRetrans to netstat default filter #1143
 * [ENHANCEMENT] Move network_up labels into new metric network_info #1236
 * [ENHANCEMENT] Use 64-bit counters for Darwin netstat
 * [BUGFIX] Add fallback for missing /proc/1/mounts #1172
 * [BUGFIX] Fix node_textfile_mtime_seconds to work properly on symlinks #1326
- Add network-online (Wants and After) dependency to systemd unit bsc#1143913

golang-github-prometheus-prometheus:

- Update change log and spec file
 + Modified spec file: default to golang 1.14 to avoid 'have choice' build issues in OBS.
 + Rebase and update patches for version 2.18.0
 + Changed:
 * 0002-Default-settings.patch Changed
- Update to 2.18.0
 + Features
 * Tracing: Added experimental Jaeger support #7148
 + Changes
 * Federation: Only use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~0.18.1~1.6.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~0.18.1~1.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~0.18.1~1.6.2", rls:"SLES12.0SP5"))) {
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
