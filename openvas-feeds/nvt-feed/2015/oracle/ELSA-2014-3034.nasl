# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123411");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-4587", "CVE-2013-6885", "CVE-2013-7266", "CVE-2014-0038", "CVE-2014-0049", "CVE-2014-0196", "CVE-2014-2309");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:27 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-3034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3034");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-35.el6uek, kernel-uek' package(s) announced via the ELSA-2014-3034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-35.el6uek]
- n_tty: Fix n_tty_write crash when echoing in raw mode (Peter Hurley) [Orabug: 18754908] {CVE-2014-0196} {CVE-2014-0196}

[3.8.13-34.el6uek]
- aacraid: missing capable() check in compat ioctl (Dan Carpenter) [Orabug: 18721960] {CVE-2013-6383}
- vhost: fix total length when packets are too short (Michael S. Tsirkin) [Orabug: 18721975] {CVE-2014-0077}

[3.8.13-33.el6uek]
- dtrace: ensure one can try to get user pages without locking or faulting (Kris Van Hees) [Orabug: 18653173]
- ipv6: don't set DST_NOCOUNT for remotely added routes (Sabrina Dubroca) [Orabug: 18681501] {CVE-2014-2309}
- kvm: x86: fix emulator buffer overflow (CVE-2014-0049) (Andrew Honig) [Orabug: 18681519] {CVE-2014-0049}
- ib_core: fmr pool hard lock up when cache enabled (Shamir Rabinovitch) [Orabug: 18408531]
- bnx2x: disable PTP clock support (Jerry Snitselaar) [Orabug: 18605376]
- x86, mm: Revert back good_end setting for 64bit (Brian Maly) [Orabug: 17648536]
- IB/sdp: disable APM by default (Shamir Rabinovitch) [Orabug: 18443201]
- vxlan: kernel panic when bringing up vxlan (Venkat Venkatsubra) [Orabug: 18295741]
- ocfs2: call ocfs2_update_inode_fsync_trans when updating any inode (Darrick J. Wong) [Orabug: 18257094]
- ocfs2: improve fsync efficiency and fix deadlock between aio_write and sync_file (Darrick J. Wong) [Orabug: 18257094]
- Revert 'ocfs2: fix i_mutex deadlock between aio_write and sync_file' (Jerry Snitselaar) [Orabug: 18257094]
- config: align with rhck (Jerry Snitselaar) [Orabug: 18685975]
- config: disable atmel drivers for ol7 (Jerry Snitselaar) [Orabug: 18665656]
- config: enable support for squashfs features (Jerry Snitselaar) [Orabug: 18655723]
- qla4xxx: Update driver version to v5.04.00.05.06.02-uek3 (Tej Parkash) [Orabug: 18552248]
- net: ipv4: current group_info should be put after using. (Wang, Xiaoming) [Orabug: 18603519] {CVE-2014-2851}

[3.8.13-32.el6uek]
- mm / dtrace: Allow DTrace to entirely disable page faults. (Nick Alcock) [Orabug: 18412802]
- mm: allow __get_user_pages() callers to avoid triggering page faults. (Nick Alcock) [Orabug: 18412802]
- config: enable nfs client support for rdma (Jerry Snitselaar) [Orabug: 18560595]
- NFS: Fix negative overflow in SETATTR timestamps (Chuck Lever) [Orabug: 18476361]
- NFS: Transfer full int64 for NFSv4 SETATTR timestamps (Chuck Lever) [Orabug: 18476361]
- NFS: Block file size updates during async READ (Chuck Lever) [Orabug: 18391310]
- NFS: Use an RPC/RDMA long request for NFS symlink operations (Chuck Lever) [Orabug: 18261861]
- SUNRPC: Support long RPC/RDMA requests (Chuck Lever) [Orabug: 18261861]
- xprtrdma: Split the completion queue (Chuck Lever) [Orabug: 18560595]
- xprtrdma: Make rpcrdma_ep_destroy() return void (Chuck Lever) [Orabug: 18560595]
- xprtrdma: Simplify rpcrdma_deregister_external() synopsis (Chuck Lever) [Orabug: 18560595]
- xprtrdma: Remove support for MEMWINDOWS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-35.el6uek, kernel-uek' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-35.el6uek", rpm:"dtrace-modules-3.8.13-35.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-headers", rpm:"dtrace-modules-headers~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-provider-headers", rpm:"dtrace-modules-provider-headers~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~35.el6uek", rls:"OracleLinux6"))) {
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
