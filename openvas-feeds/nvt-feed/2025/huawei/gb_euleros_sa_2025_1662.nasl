# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1662");
  script_cve_id("CVE-2022-48827", "CVE-2022-49046", "CVE-2022-49063", "CVE-2022-49134", "CVE-2022-49135", "CVE-2022-49160", "CVE-2022-49190", "CVE-2022-49215", "CVE-2022-49226", "CVE-2022-49390", "CVE-2022-49443", "CVE-2022-49513", "CVE-2022-49535", "CVE-2022-49536", "CVE-2022-49546", "CVE-2022-49563", "CVE-2022-49564", "CVE-2022-49566", "CVE-2022-49610", "CVE-2022-49622", "CVE-2022-49630", "CVE-2022-49632", "CVE-2022-49647", "CVE-2022-49651", "CVE-2022-49743", "CVE-2023-53008", "CVE-2023-53010", "CVE-2024-40927", "CVE-2024-42276", "CVE-2024-43867", "CVE-2024-50290", "CVE-2024-52332", "CVE-2024-53216", "CVE-2024-53680", "CVE-2024-56558", "CVE-2024-56583", "CVE-2024-56589", "CVE-2024-57929", "CVE-2024-57973", "CVE-2024-57974", "CVE-2024-57977", "CVE-2024-57979", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-57986", "CVE-2024-57996", "CVE-2024-58002", "CVE-2024-58005", "CVE-2024-58017", "CVE-2024-58069", "CVE-2024-58083", "CVE-2025-21639", "CVE-2025-21664", "CVE-2025-21666", "CVE-2025-21669", "CVE-2025-21681", "CVE-2025-21682", "CVE-2025-21687", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21700", "CVE-2025-21702", "CVE-2025-21704", "CVE-2025-21708", "CVE-2025-21719", "CVE-2025-21726", "CVE-2025-21727", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21756", "CVE-2025-21758", "CVE-2025-21759", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-21776", "CVE-2025-21779", "CVE-2025-21785", "CVE-2025-21791", "CVE-2025-21796", "CVE-2025-21806", "CVE-2025-21814", "CVE-2025-21816", "CVE-2025-21831", "CVE-2025-21846", "CVE-2025-21848", "CVE-2025-21853", "CVE-2025-21858", "CVE-2025-21861", "CVE-2025-21862", "CVE-2025-21863", "CVE-2025-21872", "CVE-2025-21877", "CVE-2025-21881", "CVE-2025-21885", "CVE-2025-21887", "CVE-2025-21898", "CVE-2025-21899", "CVE-2025-21920", "CVE-2025-21926", "CVE-2025-21927", "CVE-2025-21928", "CVE-2025-21931", "CVE-2025-21959", "CVE-2025-21971", "CVE-2025-21976", "CVE-2025-21993", "CVE-2025-21999");
  script_tag(name:"creation_date", value:"2025-06-12 10:55:30 +0000 (Thu, 12 Jun 2025)");
  script_version("2025-06-13T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-11 13:11:28 +0000 (Fri, 11 Apr 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1662)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1662");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1662");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1662 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net: gso: fix ownership in __udp_gso_segment(CVE-2025-21926)

usbnet: gl620a: fix endpoint checking in genelink_bind().(CVE-2025-21877)

net_sched: Prevent creation of classes with TC_H_ROOT(CVE-2025-21971)

fbdev: hyperv_fb: Allow graceful removal of framebuffer(CVE-2025-21976)

drm/nouveau: prime: fix refcount underflow(CVE-2024-43867)

nvme-tcp: fix potential memory corruption in nvme_tcp_recv_pdu().(CVE-2025-21927)

nvme-pci: add missing condition check for existence of mapped data(CVE-2024-42276)

ipv6: mcast: add RCU protection to mld_newpack().(CVE-2025-21758)

vlan: enforce underlying device type(CVE-2025-21920)

usb: cdc-acm: Check control transfer buffer size before access(CVE-2025-21704)

PCI: Avoid putting some root ports into D3 on TUXEDO Sirius Gen1(CVE-2025-21831)

net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21702)

netfilter: nf_conncount: Fully initialize struct nf_conncount_tuple in insert_tree().(CVE-2025-21959)

ipv4: use RCU protection in __ip_rt_update_pmtu().(CVE-2025-21766)

dm array: fix releasing a faulty array block twice in dm_array_cursor_end(CVE-2024-57929)

hwpoison, memory_hotplug: lock folio before unmap hwpoisoned folio(CVE-2025-21931)

cpufreq: governor: Use kobject release() method to free dbs_data(CVE-2022-49513)

HID: core: Fix assumption that Resolution Multipliers must be in Logical Collections(CVE-2024-57986)

ovl: fix UAF in ovl_dentry_update_reval by moving dput() in ovl_link_up(CVE-2025-21887)

xsk: Fix race at socket teardown(CVE-2022-49215)

acct: perform last write from workqueue(CVE-2025-21846)

drop_monitor: fix incorrect initialization order(CVE-2025-21862)

memcg: fix soft lockup in the OOM process(CVE-2024-57977)

rdma/cxgb4: Prevent potential integer overflow on 32bit(CVE-2024-57973)

iscsi_ibft: Fix UBSAN shift-out-of-bounds warning in ibft_attr_show_nic().(CVE-2025-21993)

x86/kexec: fix memory leak of elf header buffer(CVE-2022-49546)

proc: fix UAF in proc_get_inode().(CVE-2025-21999)

tracing: Fix bad hist from corrupting named_triggers list(CVE-2025-21899)

RDMA/bnxt_re: Fix the page details for the srq created by kernel consumers(CVE-2025-21885)

net: let net.core.dev_weight always be non-zero(CVE-2025-21806)

udp: Deal with race between UDP socket address change and rehash(CVE-2024-57974)

NFSD: Fix the behavior of READ near OFFSET_MAX(CVE-2022-48827)

dm thin: make get_first_thin use rcu-safe list first function(CVE-2025-21664)

ipv6: use RCU protection in ip6_default_advmss().(CVE-2025-21765)

xhci: Handle TD clearing for multiple streams case(CVE-2024-40927)

ipmr: do not call mr_mfc_uses_dev() for unres entries(CVE-2025-21719)

scsi: hisi_sas: Add cond_resched() for no forced preemption model(CVE-2024-56589)

net_sched: sch_sfq: don't allow 1 packet limit(CVE-2024-57996)

mm/migrate_device: don't add folio to be freed to LRU in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1905.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
