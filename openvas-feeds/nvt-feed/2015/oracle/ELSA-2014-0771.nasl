# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123391");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-6378", "CVE-2014-0203", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1874", "CVE-2014-2039", "CVE-2014-3153");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:11 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:17:50 +0000 (Tue, 02 Jul 2024)");

  script_name("Oracle: Security Advisory (ELSA-2014-0771)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0771");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0771.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-0771 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431.20.3]
- [kernel] futex: Make lookup_pi_state more robust (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}
- [kernel] futex: Always cleanup owner tid in unlock_pi (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}
- [kernel] futex: Validate atomic acquisition in futex_lock_pi_atomic() (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}
- [kernel] futex: prevent requeue pi on same futex (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}
- [fs] autofs4: fix device ioctl mount lookup (Ian Kent) [1069630 999708]
- [fs] vfs: introduce kern_path_mountpoint() (Ian Kent) [1069630 999708]
- [fs] vfs: rename user_path_umountat() to user_path_mountpoint_at() (Ian Kent) [1069630 999708]
- [fs] vfs: massage umount_lookup_last() a bit to reduce nesting (Ian Kent) [1069630 999708]
- [fs] vfs: allow umount to handle mountpoints without revalidating them (Ian Kent) [1069630 999708]
- Revert: [fs] vfs: allow umount to handle mountpoints without revalidating them (Ian Kent) [1069630 999708]
- Revert: [fs] vfs: massage umount_lookup_last() a bit to reduce nesting (Ian Kent) [1069630 999708]
- Revert: [fs] vfs: rename user_path_umountat() to user_path_mountpoint_at() (Ian Kent) [1069630 999708]
- Revert: [fs] vfs: introduce kern_path_mountpoint() (Ian Kent) [1069630 999708]
- Revert: [fs] autofs4: fix device ioctl mount lookup (Ian Kent) [1069630 999708]

[2.6.32-431.20.2]
- [block] floppy: don't write kernel-only members to FDRAWCMD ioctl output (Denys Vlasenko) [1094308 1094310] {CVE-2014-1738 CVE-2014-1737}
- [block] floppy: ignore kernel-only members in FDRAWCMD ioctl input (Denys Vlasenko) [1094308 1094310] {CVE-2014-1738 CVE-2014-1737}
- [fs] vfs: fix autofs/afs/etc magic mountpoint breakage (Frantisek Hrbata) [1094370 1079347] {CVE-2014-0203}
- [char] n_tty: Fix n_tty_write crash when echoing in raw mode (Aristeu Rozanski) [1094236 1094237] {CVE-2014-0196}

[2.6.32-431.20.1]
- [net] rtnetlink: Only supply IFLA_VF_PORTS information when RTEXT_FILTER_VF is set (Jiri Pirko) [1092870 1081282]
- [net] rtnetlink: Warn when interface's information won't fit in our packet (Jiri Pirko) [1092870 1081282]
- [net] bridge: Correctly receive hw-accelerated vlan traffic (Vlad Yasevich) [1096214 1067722]
- [net] vlan: Allow accelerated packets to flow through the bridge (Vlad Yasevich) [1096214 1067722]
- [infiniband] qib: Add missing serdes init sequence (Doug Ledford) [1080104 1005491]
- [infiniband] qib: Fix txselect regression (Doug Ledford) [1080104 1005491]
- [netdrv] ixgbevf: fix vlan acceleration (Nikolay Aleksandrov) [1094287 1069028]
- [security] selinux: Fix kernel BUG on empty security contexts (Paul Moore) [1062502 1064545] {CVE-2014-1874}
- [netdrv] libertas: potential oops in debugfs (Denys Vlasenko) [1034176 1034177] {CVE-2013-6378}
- [kernel] cgroup: move put_css_set() after setting CGRP_RELEASABLE bit to fix notify_on_release (Naoya Horiguchi) [1081909 1037465]
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.20.3.el6", rls:"OracleLinux6"))) {
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
