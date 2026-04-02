# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1339");
  script_cve_id("CVE-2022-49938", "CVE-2022-49981", "CVE-2022-49987", "CVE-2022-50080", "CVE-2022-50084", "CVE-2022-50085", "CVE-2022-50087", "CVE-2022-50127", "CVE-2022-50191", "CVE-2022-50211", "CVE-2022-50243", "CVE-2022-50252", "CVE-2022-50278", "CVE-2022-50299", "CVE-2022-50314", "CVE-2022-50352", "CVE-2022-50402", "CVE-2022-50405", "CVE-2022-50410", "CVE-2022-50449", "CVE-2022-50640", "CVE-2022-50646", "CVE-2022-50655", "CVE-2022-50671", "CVE-2022-50749", "CVE-2022-50755", "CVE-2022-50884", "CVE-2023-53148", "CVE-2023-53151", "CVE-2023-53204", "CVE-2023-53215", "CVE-2023-53234", "CVE-2023-53241", "CVE-2023-53254", "CVE-2023-53265", "CVE-2023-53271", "CVE-2023-53295", "CVE-2023-53296", "CVE-2023-53299", "CVE-2023-53313", "CVE-2023-53322", "CVE-2023-53331", "CVE-2023-53357", "CVE-2023-53372", "CVE-2023-53380", "CVE-2023-53427", "CVE-2023-53454", "CVE-2023-53481", "CVE-2023-53519", "CVE-2023-53593", "CVE-2023-53623", "CVE-2023-53675", "CVE-2023-53676", "CVE-2023-53695", "CVE-2023-53733", "CVE-2023-53786", "CVE-2023-53799", "CVE-2023-53800", "CVE-2023-53803", "CVE-2023-53817", "CVE-2023-53821", "CVE-2023-53847", "CVE-2023-53998", "CVE-2023-54014", "CVE-2023-54091", "CVE-2023-7324", "CVE-2025-21772", "CVE-2025-37834", "CVE-2025-37980", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38051", "CVE-2025-38058", "CVE-2025-38415", "CVE-2025-38445", "CVE-2025-38477", "CVE-2025-38572", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38700", "CVE-2025-38709", "CVE-2025-38724", "CVE-2025-39676", "CVE-2025-39697", "CVE-2025-39725", "CVE-2025-39773", "CVE-2025-39817", "CVE-2025-39883", "CVE-2025-39973", "CVE-2025-39998", "CVE-2025-40018", "CVE-2025-40115", "CVE-2025-40178", "CVE-2025-40196", "CVE-2025-40271", "CVE-2025-40322", "CVE-2025-68285", "CVE-2025-68349");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-08 17:39:18 +0000 (Thu, 08 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2026-1339)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1339");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1339");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2026-1339 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"media: v4l2-mem2mem: add lock to protect parameter num_rdy(CVE-2023-53519)

md: Replace snprintf with scnprintf(CVE-2022-50299)

mm/vmscan: don't try to reclaim hwpoison folio(CVE-2025-37834)

ubi: Fix unreferenced object reported by kmemleak in ubi_resize_volume()(CVE-2023-53271)

md/raid10: fix wrong setting of max_corr_read_errors(CVE-2023-53313)

scsi: target: target_core_configfs: Add length check to avoid buffer overflow(CVE-2025-39998)

loop: Avoid updating block size under exclusive owner(CVE-2025-38709)

mm/memory-failure: fix VM_BUG_ON_PAGE(PagePoisoned(page)) when unpoison memory(CVE-2025-39883)

scsi: qla4xxx: Prevent a potential error pointer dereference(CVE-2025-39676)

NFS: Fix a race when updating an existing write(CVE-2025-39697)

scsi: ses: Fix possible addl_desc_ptr out-of-bounds accesses(CVE-2023-7324)

efivarfs: Fix slab-out-of-bounds in efivarfs_d_compare(CVE-2025-39817)

dm raid: fix address sanitizer warning in raid_resume(CVE-2022-50085)

usb-storage: alauda: Fix uninit-value in alauda_check_media()(CVE-2023-53847)

mm/vmscan: fix hwpoisoned large folio handling in shrink_folio_list(CVE-2025-39725)

md/raid10: fix null-ptr-deref of mreplace in raid10_sync_request(CVE-2023-53380)

md/raid10: check slab-out-of-bounds in md_bitmap_get_counter(CVE-2023-53357)

net: sched: cls_u32: Undo tcf_bind_filter if u32_replace_hw_knode(CVE-2023-53733)

fs: quota: create dedicated workqueue for quota_release_work(CVE-2025-40196)

partitions: mac: fix handling of bogus partition table(CVE-2025-21772)

HID: hidraw: fix memory leak in hidraw_release()(CVE-2022-49981)

pid: Add a judgment for ns null in pid_nr_ns(CVE-2025-40178)

libceph: fix potential use-after-free in have_mon_and_osd_map()(CVE-2025-68285)

watchdog: Fix kmemleak in watchdog_cdev_register(CVE-2023-53234)

drivers/md/md-bitmap: check the return value of md_bitmap_get_counter()(CVE-2022-50402)

PNP: fix name memory leak in pnp_alloc_dev()(CVE-2022-50278)

ipvs: Defer ip_vs_ftp unregister during netns cleanup(CVE-2025-40018)

nbd: Fix hung when signal interrupts nbd_start_device_ioctl()(CVE-2022-50314)

igb: Do not free q_vector unless new one was allocated(CVE-2022-50252)

ubi: ubi_wl_put_peb: Fix infinite loop when wear-leveling work failed(CVE-2023-53481)

cacheinfo: Fix shared_cpu_map to handle shared caches at different levels(CVE-2023-53254)

scsi: mpt3sas: Fix crash in transport port remove by using ioc_info()(CVE-2025-40115)

scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show()(CVE-2023-53676)

NFSv4/pNFS: Clear NFS_INO_LAYOUTCOMMIT in pnfs_mark_layout_stateid_invalid(CVE-2025-68349)

net: hns: fix possible memory leak in hnae_ae_register()(CVE-2022-50352)

md: call __md_stop_writes in md_stop(CVE-2022-49987)

net/packet: fix a race in packet_set_ring() and packet_notifier()(CVE-2025-38617)

regulator: of: Fix refcount leak bug in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2141.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h2141.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2141.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2141.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h2141.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
