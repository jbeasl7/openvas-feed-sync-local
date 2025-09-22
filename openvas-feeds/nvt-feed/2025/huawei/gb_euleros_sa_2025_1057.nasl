# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1057");
  script_cve_id("CVE-2021-47344", "CVE-2021-47345", "CVE-2022-48946", "CVE-2022-48949", "CVE-2022-48956", "CVE-2022-48969", "CVE-2022-48978", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49014", "CVE-2022-49021", "CVE-2023-52653", "CVE-2023-52742", "CVE-2024-44958", "CVE-2024-45021", "CVE-2024-45025", "CVE-2024-46673", "CVE-2024-46739", "CVE-2024-46744", "CVE-2024-46750", "CVE-2024-46777", "CVE-2024-46826", "CVE-2024-46829", "CVE-2024-46859", "CVE-2024-47685", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47701", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-49855", "CVE-2024-49860", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49889", "CVE-2024-49894", "CVE-2024-49959", "CVE-2024-49995", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50073", "CVE-2024-50115", "CVE-2024-50154", "CVE-2024-50179", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50258", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50301");
  script_tag(name:"creation_date", value:"2025-01-14 15:21:42 +0000 (Tue, 14 Jan 2025)");
  script_version("2025-01-15T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1057");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1057");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory(CVE-2024-50115)

tcp/dccp: Don't use timer_pending() in reqsk_queue_unlink().(CVE-2024-50154)

bpf: Fix out-of-bounds write in trie_get_next_key().(CVE-2024-50262)

security/keys: fix slab-out-of-bounds in key_task_permission(CVE-2024-50301)

dm cache: fix potential out-of-bounds access on the first resume(CVE-2024-50278)

dm cache: fix out-of-bounds access to the dirty bitset when resizing(CVE-2024-50279)

fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE(CVE-2024-45025)

net: USB: Fix wrong-direction WARNING in plusb.c (CVE-2023-52742)

In the Linux kernel, the following vulnerability has been resolved:memcg_write_event_control(): fix a user-triggerable oops we are *not* guaranteed that anything past the terminating NUL is mapped (let alone initialized with anything sane).(CVE-2024-45021)

udf: Avoid excessive partition lengths(CVE-2024-46777)

uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (CVE-2024-46739)

Squashfs: sanity check symbolic link size(CVE-2024-46744)

PCI: Add missing bridge lock to pci_bus_lock()(CVE-2024-46750)

platform/x86: panasonic-laptop: Fix SINF array out of bounds accesses(CVE-2024-46859)

ELF: fix kernel.randomize_va_space double read(CVE-2024-46826)

rtmutex: Drop rt_mutex::wait_lock before scheduling(CVE-2024-46829)

sched/smt: Fix unbalance sched_smt_present dec/inc(CVE-2024-44958)

scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

media: zr364xx: fix memory leak in zr364xx_start_readpipe(CVE-2021-47344)

RDMA/cma: Fix rdma_resolve_route() memory leak(CVE-2021-47345)

ACPI: sysfs: validate return type of _STR method(CVE-2024-49860)

mm: call the security_mmap_file() LSM hook in remap_file_pages().(CVE-2024-47745)

netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()(CVE-2024-47685)

drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error(CVE-2024-47697)

drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error(CVE-2024-47698)

tipc: guard against string buffer overrun(CVE-2024-49995)

ext4: fix double brelse() the buffer of the extents path(CVE-2024-49882)

net: tun: Fix use-after-free in tun_detach()(CVE-2022-49014)

ppp: fix ppp_async_encode() illegal access(CVE-2024-50035)

serial: protect uart_port_dtr_rts() in uart_shutdown() too(CVE-2024-50058)

net: do not delay dst_entries_add() in dst_release()(CVE-2024-50036)

HID: core: fix shift-out-of-bounds in hid_report_raw_event(CVE-2022-48978)

slip: make slhc_remember() more robust against malicious packets(CVE-2024-50033)

ipv6: avoid use-after-free in ip6_fragment()(CVE-2022-48956)

udf: Fix preallocation discarding at indirect extent boundary(CVE-2022-48946)

net: phy: fix null-ptr-deref while probe() failed(CVE-2022-49021)

igb: Initialize mailbox message for VF reset(CVE-2022-48949)

xen-netfront: Fix NULL sring after live ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h1486.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h1486.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h1486.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h1486.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
