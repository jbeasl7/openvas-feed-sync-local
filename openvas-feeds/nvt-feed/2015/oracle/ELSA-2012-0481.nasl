# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123936");
  script_cve_id("CVE-2012-0879", "CVE-2012-1090", "CVE-2012-1097");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:32 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:14:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-0481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0481");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0481.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-0481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-220.13.1.el6]
- Revert: [fs] NFSv4: include bitmap in nfsv4 get acl data (Sachin Prabhu) [753231 753232] {CVE-2011-4131}

[2.6.32-220.12.1.el6]
- [net] net_sched: qdisc_alloc_handle() can be too slow (Jiri Pirko) [805458 785891]
- [fs] procfs: add hidepid= and gid= mount options (Jerome Marchand) [770651 770652]
- [fs] procfs: parse mount options (Jerome Marchand) [770651 770652]
- [fs] fuse: add O_DIRECT support (Josef Bacik) [800552 753798]
- [kernel] sysctl: restrict write access to dmesg_restrict (Phillip Lougher) [749248 749251]
- [block] dm io: fix discard support (Mike Snitzer) [799943 758404]
- [net] netlink: wrong size was calculated for vfinfo list blob (Andy Gospodarek) [790338 772136]
- [netdrv] mlx4_en: fix endianness with blue frame support (Steve Best) [789911 750166]
- [usb] Fix deadlock in hid_reset when Dell iDRAC is reset (Shyam Iyer) [797205 782374]
- [virt] vmxnet3: Cap the length of the pskb_may_pull on transmit (bz 790673) (Neil Horman) [801723 790673]
- [scsi] megaraid_sas: Fix instance access in megasas_reset_timer (Tomas Henzl) [790341 759318]
- [netdrv] macvtap: Fix the minor device number allocation (Steve Best) [796828 786518]
- [net] tcp: bind() fix autoselection to share ports (Flavio Leitner) [787764 784671]
- [fs] cifs: change oplock break slow work to very slow work (Jeff Layton) [789373 772874]
- [net] sunrpc: remove xpt_pool (J. Bruce Fields) [795338 753301]
- [net] Potential null skb->dev dereference (Flavio Leitner) [795335 769590]
- [net] pkt_sched: Fix sch_sfq vs tcf_bind_filter oops (Jiri Pirko) [786873 667925]
- [net] mac80211: cancel auth retries when deauthenticating (John Linville) [797241 754356]

[2.6.32-220.11.1.el6]
- [netdrv] igb: reset PHY after recovering from PHY power down (Frantisek Hrbata) [789371 737714]
- [drm] Ivybridge force wake fixes (Dave Airlie) [790007 786272]
- [fs] xfs: fix inode lookup race (Dave Chinner) [804961 796277]
- [kernel] regset: Return -EFAULT, not -EIO, on host-side memory fault (Jerome Marchand) [799212 799213] {CVE-2012-1097}
- [kernel] regset: Prevent null pointer reference on readonly regsets (Jerome Marchand) [799212 799213] {CVE-2012-1097}
- [block] Fix io_context leak after failure of clone with CLONE_IO (Vivek Goyal) [796846 791125] {CVE-2012-0879}
- [block] Fix io_context leak after clone with CLONE_IO (Vivek Goyal) [796846 791125] {CVE-2012-0879}
- [fs] cifs: fix dentry refcount leak when opening a FIFO on lookup (Sachin Prabhu) [798298 781893] {CVE-2012-1090}
- [fs] NFSv4: include bitmap in nfsv4 get acl data (Sachin Prabhu) [753231 753232] {CVE-2011-4131}
- [mm] fix nrpages assertion (Josef Bacik) [797182 766861]
- [mm] Eliminate possible panic in page compaction code (Larry Woodman) [802430 755885]
- [mm] Prevent panic on 2-node x3850 X5 w/2 MAX5 memory drawers panics while running certification tests caused by page list corruption (Larry Woodman) [802430 755885]
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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.13.1.el6", rls:"OracleLinux6"))) {
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
