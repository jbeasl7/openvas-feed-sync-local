# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2100");
  script_cve_id("CVE-2022-49626", "CVE-2022-49769", "CVE-2022-49771", "CVE-2022-49787", "CVE-2022-49788", "CVE-2022-49826", "CVE-2022-49846", "CVE-2022-49862", "CVE-2022-49865", "CVE-2022-49874", "CVE-2022-49903", "CVE-2022-49907", "CVE-2022-49921", "CVE-2022-49982", "CVE-2022-49986", "CVE-2022-49987", "CVE-2022-49989", "CVE-2022-50022", "CVE-2022-50053", "CVE-2022-50066", "CVE-2022-50093", "CVE-2022-50098", "CVE-2022-50103", "CVE-2022-50127", "CVE-2022-50202", "CVE-2022-50211", "CVE-2022-50220", "CVE-2022-50228", "CVE-2023-53062", "CVE-2023-53091", "CVE-2023-53116", "CVE-2023-53125", "CVE-2023-53146", "CVE-2024-57982", "CVE-2025-21759", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-23150", "CVE-2025-37834", "CVE-2025-37932", "CVE-2025-37980", "CVE-2025-37995", "CVE-2025-38000", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38035", "CVE-2025-38051", "CVE-2025-38058", "CVE-2025-38063", "CVE-2025-38079", "CVE-2025-38086", "CVE-2025-38212", "CVE-2025-38215", "CVE-2025-38229", "CVE-2025-38312", "CVE-2025-38337");
  script_tag(name:"creation_date", value:"2025-09-10 04:27:54 +0000 (Wed, 10 Sep 2025)");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-07 13:27:50 +0000 (Wed, 07 May 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2100)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2100");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2100");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2100 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KVM: SVM: Don't BUG if userspace injects an interrupt with GIF=0(CVE-2022-50228)

md: call __md_stop_writes in md_stop(CVE-2022-49987)

iommu/vt-d: avoid invalid memory access via node_online(NUMA_NO_NODE).(CVE-2022-50093)

block: fix resource leak in blk_register_queue() error path.(CVE-2025-37980)

media: dw2102: Fix null-ptr-deref in dw2102_i2c_transfer().(CVE-2023-53146)

net: atlantic: fix aq_vec index out of range error(CVE-2022-50066)

ext4: update s_journal_inum if it changes after journal replay(CVE-2023-53091)

dm: fix unconditional IO throttle caused by REQ_PREFLUSH(CVE-2025-38063)

openvswitch: use RCU protection in ovs_vport_cmd_fill_info().(CVE-2025-21761)

nfs: handle failure of nfs_get_lock_context in unlock path(CVE-2025-38023)

dm ioctl: fix misbehavior if list_versions races with module loading(CVE-2022-49771)

arp: use RCU protection in arp_xmit().(CVE-2025-21762)

ipv6: fix WARNING in ip6_route_net_exit_late().(CVE-2022-49903)

fbdev: core: fbcvt: avoid division by 0 in fb_cvt_hperiod().(CVE-2025-38312)

__legitimize_mnt(): check for MNT_SYNC_UMOUNT should be under mount_lock(CVE-2025-38058)

crypto: algif_hash - fix double free in hash_accept(CVE-2025-38079)

net: ch9200: fix uninitialised access during mii_nway_restart(CVE-2025-38086)

mm/vmscan: don't try to reclaim hwpoison folio(CVE-2025-37834)

udf: Fix a slab-out-of-bounds write bug in udf_find_entry().(CVE-2022-49846)

scsi: qla2xxx: Fix crash due to stale SRB access around I/O timeouts(CVE-2022-50098)

nvmet: avoid potential UAF in nvmet_req_complete().(CVE-2023-53116)

media: pvrusb2: fix memory leak in pvr_probe(CVE-2022-49982)

neighbour: use RCU protection in __neigh_notify().(CVE-2025-21763)

net: usb: smsc95xx: Limit packet length to skb->len(CVE-2023-53062)

nvmet-tcp: don't restore null sk_state_change(CVE-2025-38035)

RDMA/rxe: Fix error unwind in rxe_create_qp().(CVE-2022-50127)

ext4: fix off-by-one error in do_split(CVE-2025-23150)

net: mdio: fix undefined behavior in bit shift for __mdiobus_register(CVE-2022-49907)

jbd2: fix data-race and null-ptr-deref in jbd2_journal_dirty_metadata().(CVE-2025-38337)

drivers:md:fix a potential use-after-free bug(CVE-2022-50022)

PM: hibernate: defer device probing when resuming from hibernation(CVE-2022-50202)

mmc: sdhci-pci: Fix possible memory leak caused by missing pci_dev_put().(CVE-2022-49787)

gfs2: Check sb_bsize_shift after reading superblock(CVE-2022-49769)

sch_htb: make htb_qlen_notify() idempotent(CVE-2025-37932)

usbnet: Fix linkwatch use-after-free on disconnect(CVE-2022-50220)

xfrm: state: fix out-of-bounds read during lookup(CVE-2024-57982)

ndisc: extend RCU protection in ndisc_send_skb().(CVE-2025-21760)

ndisc: use RCU protection in ndisc_alloc_skb().(CVE-2025-21764)

sched, cpuset: Fix dl_cpu_busy() panic due to empty cs->cpus_allowed(CVE-2022-50103)

tipc: fix the msg->req tlv len check in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1885.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1885.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1885.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1885.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1885.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
