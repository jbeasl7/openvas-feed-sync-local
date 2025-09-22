# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1267");
  script_cve_id("CVE-2021-47356", "CVE-2024-50150", "CVE-2024-50167", "CVE-2024-50194", "CVE-2024-50251", "CVE-2024-50264", "CVE-2024-50267", "CVE-2024-50299", "CVE-2024-50302", "CVE-2024-53057", "CVE-2024-53066", "CVE-2024-53095", "CVE-2024-53103", "CVE-2024-53104", "CVE-2024-53140", "CVE-2024-53141", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53168", "CVE-2024-53173", "CVE-2024-53194", "CVE-2024-53214", "CVE-2024-53217", "CVE-2024-53240", "CVE-2024-56570", "CVE-2024-56615", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56647", "CVE-2024-56664", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56739", "CVE-2024-56747", "CVE-2024-56780", "CVE-2024-57883", "CVE-2024-57931");
  script_tag(name:"creation_date", value:"2025-03-17 15:44:41 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-08 21:37:23 +0000 (Wed, 08 Jan 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1267");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1267");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"initramfs: avoid filename buffer overrun(CVE-2024-53142)

scsi: sg: Fix slab-use-after-free read in sg_release()(CVE-2024-56631)

bpf, sockmap: Fix race between element replace and close()(CVE-2024-56664)

mISDN: fix possible use-after-free in HFC_cleanup()(CVE-2021-47356)

sctp: properly validate chunk size in sctp_sf_ootb().(CVE-2024-50299)

bpf: fix OOB devmap writes when deleting elemen(CVE-2024-56615)

nfs: Fix KMSAN warning in decode_getfattr_attrs().(CVE-2024-53066)

arm64: probes: Fix uprobes for big-endian kernels(CVE-2024-50194)

NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format(CVE-2024-53104)

USB: serial: io_edgeport: fix use after free in debug printk(CVE-2024-50267)

tipc: Fix use-after-free of kernel socket in cleanup_bearer().(CVE-2024-56642)

usb: typec: altmode should keep reference to parent(CVE-2024-50150)

smb: client: Fix use-after-free of network namespace.(CVE-2024-53095)

net: Fix icmp host relookup triggering ip_rt_bug(CVE-2024-56647)

be2net: fix potential memory leak in be_xmit().(CVE-2024-50167)

crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY(CVE-2024-56690)

vfio/pci: Properly hide first-in-list PCIe extended capability(CVE-2024-53214)

vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans(CVE-2024-50264)

HID: core: zero-initialize the report buffer(CVE-2024-50302)

NFSD: Prevent a potential integer overflow(CVE-2024-53146)

hv_sock: Initializing vsk->trans to NULL to prevent a dangling pointer(CVE-2024-53103)

netlink: terminate outstanding dump on socket close(CVE-2024-53140)

sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket(CVE-2024-53168)

PCI: Fix use-after-free of slot->bus on hot remove(CVE-2024-53194)

net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT(CVE-2024-53057)

NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport(CVE-2024-56688)

netfilter: nft_payload: sanitize offset and length before calling skb_checksum().(CVE-2024-50251)

netfilter: ipset: add missing range check in bitmap_ip_uadt(CVE-2024-53141)

xen
etfront: fix crash when removing device(CVE-2024-53240)

scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb()(CVE-2024-56747)

ovl: Filter invalid inodes with missing lookup function(CVE-2024-56570)

rtc: check if __rtc_read_time was successful in rtc_timer_do_work()(CVE-2024-56739)

quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

selinux: ignore unknown extended permissions(CVE-2024-57931)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h1511.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h1511.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h1511.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h1511.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
