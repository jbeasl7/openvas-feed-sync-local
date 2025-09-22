# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1826");
  script_cve_id("CVE-2022-49267", "CVE-2022-49513", "CVE-2022-49546", "CVE-2022-49579", "CVE-2022-49722", "CVE-2022-49743", "CVE-2023-52928", "CVE-2023-53001", "CVE-2023-53008", "CVE-2023-53010", "CVE-2024-52332", "CVE-2024-56589", "CVE-2024-57929", "CVE-2024-57951", "CVE-2024-57974", "CVE-2024-57982", "CVE-2024-57996", "CVE-2025-21664", "CVE-2025-21702", "CVE-2025-21704", "CVE-2025-21719", "CVE-2025-21750", "CVE-2025-21758", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-21806", "CVE-2025-21831", "CVE-2025-21861", "CVE-2025-21872", "CVE-2025-21877", "CVE-2025-21881", "CVE-2025-21885", "CVE-2025-21891", "CVE-2025-21898", "CVE-2025-21899", "CVE-2025-21920", "CVE-2025-21922", "CVE-2025-21926", "CVE-2025-21927", "CVE-2025-21928", "CVE-2025-21931", "CVE-2025-21959", "CVE-2025-21971", "CVE-2025-21975", "CVE-2025-21976", "CVE-2025-21981", "CVE-2025-21993", "CVE-2025-22005", "CVE-2025-22008", "CVE-2025-22026", "CVE-2025-22027", "CVE-2025-22063", "CVE-2025-22090", "CVE-2025-22113", "CVE-2025-22121", "CVE-2025-23131", "CVE-2025-23136", "CVE-2025-23150", "CVE-2025-37752", "CVE-2025-37785", "CVE-2025-37807", "CVE-2025-39728");
  script_tag(name:"creation_date", value:"2025-07-21 04:42:46 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-11 13:11:28 +0000 (Fri, 11 Apr 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1826)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1826");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1826");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1826 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ovl: Use 'buf' flexible array for memcpy() destination(CVE-2022-49743)

cifs: fix potential memory leaks in session setup(CVE-2023-53008)

bnxt: Do not read past the end of test names(CVE-2023-53010)

uprobes: Reject the shared zeropage in uprobe_write_opcode().(CVE-2025-21881)

ftrace: Avoid potential division by zero in function_stat_show().(CVE-2025-21898)

igb: Fix potential invalid memory access in igb_init_module().(CVE-2024-52332)

bpf: Skip invalid kfunc call in backtrack_insn(CVE-2023-52928)

HID: intel-ish-hid: Fix use-after-free issue in ishtp_hid_remove().(CVE-2025-21928)

efi: Don't map the entire mokvar table to determine its size(CVE-2025-21872)

mm/migrate_device: don't add folio to be freed to LRU in migrate_device_finalize().(CVE-2025-21861)

net_sched: sch_sfq: don't allow 1 packet limit(CVE-2024-57996)

scsi: hisi_sas: Add cond_resched() for no forced preemption model(CVE-2024-56589)

ipmr: do not call mr_mfc_uses_dev() for unres entries(CVE-2025-21719)

dm thin: make get_first_thin use rcu-safe list first function(CVE-2025-21664)

ipvlan: ensure network headers are in skb linear part(CVE-2025-21891)

net/mlx5: handle errors in mlx5_chains_create_table().(CVE-2025-21975)

ppp: Fix KMSAN uninit-value warning with bpf(CVE-2025-21922)

udp: Deal with race between UDP socket address change and rehash(CVE-2024-57974)

net: let net.core.dev_weight always be non-zero(CVE-2025-21806)

RDMA/bnxt_re: Fix the page details for the srq created by kernel consumers(CVE-2025-21885)

tracing: Fix bad hist from corrupting named_triggers list(CVE-2025-21899)

ipv6: use RCU protection in ip6_default_advmss().(CVE-2025-21765)

x86/kexec: fix memory leak of elf header buffer(CVE-2022-49546)

regulator: check that dummy regulator has been probed before using it(CVE-2025-22008)

iscsi_ibft: Fix UBSAN shift-out-of-bounds warning in ibft_attr_show_nic().(CVE-2025-21993)

ipv6: Fix memleak of nhc_pcpu_rth_output in fib_check_nh_v6_gw().(CVE-2025-22005)

drm/drm_vma_manager: Add drm_vma_node_allow_once().(CVE-2023-53001)

ext4: avoid journaling sb update on error if journal is destroying(CVE-2025-22113)

ext4: fix out-of-bound read in ext4_xattr_inode_dec_ref_all().(CVE-2025-22121)

nfsd: don't ignore the return code of svc_proc_register().(CVE-2025-22026)

ipv4: Fix data-races around sysctl_fib_multipath_hash_policy.(CVE-2022-49579)

thermal: int340x: Add NULL check for adev(CVE-2025-23136)

dlm: prevent NPD when writing a positive value to event_done(CVE-2025-23131)

ext4: fix OOB read when checking dotdot dir(CVE-2025-37785)

mmc: core: use sysfs_emit() instead of sprintf().(CVE-2022-49267)

wifi: brcmfmac: Check the return value of of_property_read_string_index().(CVE-2025-21750)

media: streamzap: fix race between device disconnection and urb callback(CVE-2025-22027)

hrtimers: Handle CPU state correctly on hotplug(CVE-2024-57951)

x86/mm/pat: Fix VM_PAT handling when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2615.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
