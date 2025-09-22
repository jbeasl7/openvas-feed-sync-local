# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123581");
  script_cve_id("CVE-2012-6544", "CVE-2013-2146", "CVE-2013-2206", "CVE-2013-2224", "CVE-2013-2232", "CVE-2013-2237");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:49 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1173");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1173.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-1173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.18.1]
- [x86] perf/x86: Fix offcore_rsp valid mask for SNB/IVB (Nikola Pajkovsky) [971314 971315] {CVE-2013-2146}
- [net] br: fix schedule while atomic issue in br_features_recompute() (Jiri Pirko) [990464 980876]
- [scsi] isci: Fix a race condition in the SSP task management path (David Milburn) [990470 978609]
- [bluetooth] L2CAP - Fix info leak via getsockname() (Jacob Tanenbaum) [922417 922418] {CVE-2012-6544}
- [bluetooth] HCI - Fix info leak in getsockopt() (Jacob Tanenbaum) [922417 922418] {CVE-2012-6544}
- [net] tuntap: initialize vlan_features (Vlad Yasevich) [984524 951458]
- [net] af_key: initialize satype in key_notify_policy_flush() (Thomas Graf) [981225 981227] {CVE-2013-2237}
- [usb] uhci: fix for suspend of virtual HP controller (Gopal) [982697 960026]
- [usb] uhci: Remove PCI dependencies from uhci-hub (Gopal) [982697 960026]
- [netdrv] bnx2x: Change MDIO clock settings (Michal Schmidt) [982116 901747]
- [scsi] st: Take additional queue ref in st_probe (Tomas Henzl) [979293 927988]
- [kernel] audit: wait_for_auditd() should use TASK_UNINTERRUPTIBLE (Oleg Nesterov) [982472 962976]
- [kernel] audit: avoid negative sleep durations (Oleg Nesterov) [982472 962976]
- [fs] ext4/jbd2: don't wait (forever) for stale tid caused by wraparound (Eric Sandeen) [963557 955807]
- [fs] jbd: don't wait (forever) for stale tid caused by wraparound (Eric Sandeen) [963557 955807]
- [fs] ext4: fix waiting and sending of a barrier in ext4_sync_file() (Eric Sandeen) [963557 955807]
- [fs] jbd2: Add function jbd2_trans_will_send_data_barrier() (Eric Sandeen) [963557 955807]
- [fs] jbd2: fix sending of data flush on journal commit (Eric Sandeen) [963557 955807]
- [fs] ext4: fix fdatasync() for files with only i_size changes (Eric Sandeen) [963557 955807]
- [fs] ext4: Initialize fsync transaction ids in ext4_new_inode() (Eric Sandeen) [963557 955807]
- [fs] ext4: Rewrite __jbd2_log_start_commit logic to match upstream (Eric Sandeen) [963557 955807]
- [net] bridge: Set vlan_features to allow offloads on vlans (Vlad Yasevich) [984524 951458]
- [virt] virtio-net: initialize vlan_features (Vlad Yasevich) [984524 951458]
- [mm] swap: avoid read_swap_cache_async() race to deadlock while waiting on discard I/O completion (Rafael Aquini) [977668 827548]
- [dma] ioat: Fix excessive CPU utilization (John Feeney) [982758 883575]
- [fs] vfs: revert most of dcache remove d_mounted (Ian Kent) [974597 907512]
- [fs] xfs: don't free EFIs before the EFDs are committed (Carlos Maiolino) [975578 947582]
- [fs] xfs: pass shutdown method into xfs_trans_ail_delete_bulk (Carlos Maiolino) [975576 805407]
- [net] ipv6: bind() use stronger condition for bind_conflict (Flavio Leitner) [989923 917872]
- [net] tcp: bind() use stronger condition for bind_conflict (Flavio Leitner) [977680 894683]
- [x86] remove BUG_ON(TS_USEDFPU) in __sanitize_i387_state() (Oleg Nesterov) [956054 920445]
- [fs] ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.18.1.el6", rls:"OracleLinux6"))) {
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
