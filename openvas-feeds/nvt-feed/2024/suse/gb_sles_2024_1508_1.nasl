# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1508.1");
  script_cve_id("CVE-2023-6152", "CVE-2024-1313");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-21 18:35:59 +0000 (Mon, 21 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1508-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1508-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241508-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222155");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035169.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2024:1508-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-prometheus-node_exporter:

- Update to 1.7.0 (jsc#PED-7893, jsc#PED-7928):
 * [FEATURE] Add ZFS freebsd per dataset stats #2753
 * [FEATURE] Add cpu vulnerabilities reporting from sysfs #2721
 * [ENHANCEMENT] Parallelize stat calls in Linux filesystem
 collector #1772
 * [ENHANCEMENT] Add missing linkspeeds to ethtool collector #2711
 * [ENHANCEMENT] Add CPU MHz as the value for node_cpu_info metric
 #2778
 * [ENHANCEMENT] Improve qdisc collector performance #2779
 * [ENHANCEMENT] Add include and exclude filter for hwmon
 collector #2699
 * [ENHANCEMENT] Optionally fetch ARP stats via rtnetlink instead
 of procfs #2777
 * [BUFFIX] Fix ZFS arcstats on FreeBSD 14.0+ 2754
 * [BUGFIX] Fallback to 32-bit stats in netdev #2757
 * [BUGFIX] Close btrfs.FS handle after use #2780
 * [BUGFIX] Move RO status before error return #2807
 * [BUFFIX] Fix promhttp_metric_handler_errors_total being always
 active #2808
 * [BUGFIX] Fix nfsd v4 index miss #2824
- Update to 1.6.1:
 (no source code changes in this release)
- BuildRequire go1.20
- Update to 1.6.0:
 * [CHANGE] Fix cpustat when some cpus are offline #2318
 * [CHANGE] Remove metrics of offline CPUs in CPU collector #2605
 * [CHANGE] Deprecate ntp collector #2603
 * [CHANGE] Remove bcache `cache_readaheads_totals` metrics #2583
 * [CHANGE] Deprecate supervisord collector #2685
 * [FEATURE] Enable uname collector on NetBSD #2559
 * [FEATURE] NetBSD support for the meminfo collector #2570
 * [FEATURE] NetBSD support for CPU collector #2626
 * [FEATURE] Add FreeBSD collector for netisr subsystem #2668
 * [FEATURE] Add softirqs collector #2669
 * [ENHANCEMENT] Add suspended as a `node_zfs_zpool_state` #2449
 * [ENHANCEMENT] Add administrative state of Linux network
 interfaces #2515
 * [ENHANCEMENT] Log current value of GOMAXPROCS #2537
 * [ENHANCEMENT] Add profiler options for perf collector #2542
 * [ENHANCEMENT] Allow root path as metrics path #2590
 * [ENHANCEMENT] Add cpu frequency governor metrics #2569
 * [ENHANCEMENT] Add new landing page #2622
 * [ENHANCEMENT] Reduce privileges needed for btrfs device stats
 #2634
 * [ENHANCEMENT] Add ZFS `memory_available_bytes` #2687
 * [ENHANCEMENT] Use `SCSI_IDENT_SERIAL` as serial in diskstats
 #2612
 * [ENHANCEMENT] Read missing from netlink netclass attributes
 from sysfs #2669
 * [BUGFIX] perf: fixes for automatically detecting the correct
 tracefs mountpoints #2553
 * [BUGFIX] Fix `thermal_zone` collector noise @2554
 * [BUGFIX] Fix a problem fetching the user wire count on FreeBSD
 2584
 * [BUGFIX] interrupts: Fix fields on linux aarch64 #2631
 * [BUGFIX] Remove metrics of offline CPUs in CPU collector #2605
 * [BUGFIX] Fix OpenBSD filesystem collector string parsing #2637
 * [BUGFIX] Fix bad reporting of `node_cpu_seconds_total` in
 OpenBSD #2663
- Change go_modules archive in _service to use obscpio file

grafana:

- Packaging ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.7.0~1.30.2", rls:"SLES12.0SP5"))) {
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
