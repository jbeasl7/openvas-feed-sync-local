# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123812");
  script_cve_id("CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:53 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:33:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-1304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1304");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1304.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-1304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-279.9.1.el6]
- [md] raid1, raid10: avoid deadlock during resync/recovery. (Dave Wysochanski) [845464 835613]
- [fs] dlm: fix deadlock between dlm_send and dlm_controld (David Teigland) [849051 824964]
- [ata] libata: Add space to fix 2GB ATA Flash Disk/ADMA428M blacklist (Prarit Bhargava) [851445 843849]
- [fs] nfs: nfs_attr_use_mounted_on_file() missing return value (Frantisek Hrbata) [847945 842312]
- [fs] gfs2: Make gfs2_write_end not dirty the inode with every write (Robert S Peterson) [849551 844814]
- [net] sched/act_mirred: do not drop packets when fails to mirror it (Jason Wang) [851444 846585]
- [net] sched: fix race in mirred device removal (Jason Wang) [851444 846585]
- [net] sched: printk message severity (Jason Wang) [851444 846585]
- [net] sched: act_mirred cleanup (Jason Wang) [851444 846585]
- [kernel] sched: Fix signed unsigned comparison in check_preempt_tick() (Frederic Weisbecker) [843102 835797]
- [netdrv] be2net: reduce gso_max_size setting to account for ethernet header (Ivan Vecera) [842757 834185]
- [powerpc] Fix wrong divisor in usecs_to_cputime backport (Steve Best) [847727 821374]
- [fs] procfs: do not confuse jiffies with cputime64_t (Frantisek Hrbata) [847727 821374]
- [kernel] time: Add nsecs_to_cputime64 interface for asm-generic (Steve Best) [847727 821374]
- [powerpc] Fix wrong divisor in usecs_to_cputime (Steve Best) [847727 821374]

[2.6.32-279.8.1.el6]
- [netdrv] e1000e: prevent oops when adapter is being closed and reset simultaneously (Dean Nelson) [847045 826375]
- [net] tcp: clear hints to avoid a stale one (Andy Gospodarek) [846832 807704]
- [md] dm-raid1: Fix mirror crash when discard request is sent and sync is in progress (Mikulas Patocka) [846839 837607]
- [netdrv] bond_alb: don't disable softirq under bond_alb_xmit (Jiri Pirko) [846216 841987]
- [x86] ioapic: Fix kdump race with migrating irq (Don Zickus) [812962 783322]
- [net] rds: set correct msg_namelen (Weiping Pan) [822729 822731] {CVE-2012-3430}
- [x86] amd_iommu: Fix SRIOV and hotplug devices (Stefan Assmann) [846838 832009]
- [mm] hugetlb: fix resv_map leak in error path (Motohiro Kosaki) [824350 824351] {CVE-2012-2390}
- [netdrv] dl2k: fix unfiltered netdev rio_ioctl access by users (Jacob Tanenbaum) [818824 818825] {CVE-2012-2313}
- [drm] i915: fix integer overflow in i915_gem_do_execbuffer() (Jacob Tanenbaum) [824561 824563] {CVE-2012-2384}
- [virt] kvm: handle last_boosted_vcpu = 0 case (Rik van Riel) [847042 827031]
- [md] raid5: Reintroduce locking in handle_stripe() to avoid racing (Jes Sorensen) [846836 828065]
- [kernel] timekeeping: Fix leapsecond triggered load spike issue (Prarit Bhargava) [847366 840950 836803 836748]
- [kernel] hrtimer: Provide clock_was_set_delayed() (Prarit Bhargava) [847366 840950 836803 836748]
- [kernel] ntp: Add ntp_lock to replace xtime_locking (Prarit Bhargava) [847366 840950 836803 836748]
- [fs] proc/stat: fix ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.9.1.el6", rls:"OracleLinux6"))) {
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
