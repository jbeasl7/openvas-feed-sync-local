# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1024");
  script_cve_id("CVE-2021-47344", "CVE-2021-47345", "CVE-2022-48946", "CVE-2022-48949", "CVE-2022-48969", "CVE-2022-48978", "CVE-2022-48988", "CVE-2022-49000", "CVE-2022-49002", "CVE-2024-44958", "CVE-2024-45021", "CVE-2024-45025", "CVE-2024-46673", "CVE-2024-46739", "CVE-2024-46744", "CVE-2024-46750", "CVE-2024-46777", "CVE-2024-46826", "CVE-2024-46829", "CVE-2024-46859", "CVE-2024-47685", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47701", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-49855", "CVE-2024-49860", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49889", "CVE-2024-49894", "CVE-2024-49959", "CVE-2024-49995", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50073", "CVE-2024-50115", "CVE-2024-50154", "CVE-2024-50179", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50258", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50301");
  script_tag(name:"creation_date", value:"2025-01-14 04:31:02 +0000 (Tue, 14 Jan 2025)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1024");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1024");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RDMA/cma: Fix rdma_resolve_route() memory leak(CVE-2021-47345)

HID: usbhid: free raw_report buffers in usbhid_stop(CVE-2021-47405)

net: fix information leakage in /proc/ net/ptype(CVE-2022-48757)

USB: core: Fix hang in usb_kill_urb by adding memory barriers(CVE-2022-48760)

udf: Fix preallocation discarding at indirect extent boundary(CVE-2022-48946)

igb: Initialize mailbox message for VF reset(CVE-2022-48949)

HID: core: fix shift-out-of-bounds in hid_report_raw_event(CVE-2022-48978)

memcg: fix possible use-after-free in memcg_write_event_control().(CVE-2022-48988)

ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound(CVE-2024-33621)

netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get().(CVE-2024-35898)

rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation(CVE-2024-36017)

nsh: Restore skb->{protocol,data,mac_header} for outer header in nsh_gso_segment().(CVE-2024-36933)

scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory(CVE-2024-40901)

drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes(CVE-2024-41089)

memcg_write_event_control(): fix a user-triggerable oops(CVE-2024-45021)

fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE(CVE-2024-45025)

scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

pinctrl: single: fix potential NULL dereference in pcs_get_function().(CVE-2024-46685)

of/irq: Prevent device address out-of-bounds read in interrupt map walk(CVE-2024-46743)

Squashfs: sanity check symbolic link size(CVE-2024-46744)

PCI: Add missing bridge lock to pci_bus_lock().(CVE-2024-46750)

udf: Avoid excessive partition lengths(CVE-2024-46777)

drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links(CVE-2024-46816)

ELF: fix kernel.randomize_va_space double read(CVE-2024-46826)

rtmutex: Drop rt_mutex::wait_lock before scheduling(CVE-2024-46829)

netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put().(CVE-2024-47685)

RDMA/iwcm: Fix WARNING:at_kernel/workqueue.c:#check_flush_dependency(CVE-2024-47696)

ext4: avoid OOB when system.data xattr changes underneath the filesystem(CVE-2024-47701)

firmware_loader: Block path traversal(CVE-2024-47742)

mm: call the security_mmap_file() LSM hook in remap_file_pages().(CVE-2024-47745)

nbd: fix race between timeout and normal completion(CVE-2024-49855)

ACPI: sysfs: validate return type of _STR method(CVE-2024-49860)

ext4: update orig_path in ext4_find_extent().(CVE-2024-49881)

ext4: fix double brelse() the buffer of the extents path(CVE-2024-49882)

ext4: aovid use-after-free in ext4_ext_insert_extent().(CVE-2024-49883)

ext4: fix slab-use-after-free in ext4_split_extent_at().(CVE-2024-49884)

ext4: avoid use-after-free in ext4_ext_show_leaf().(CVE-2024-49889)

jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error(CVE-2024-49959)

slip: make slhc_remember() more ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
