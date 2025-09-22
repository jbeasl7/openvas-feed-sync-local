# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2929");
  script_cve_id("CVE-2022-48790", "CVE-2022-48828", "CVE-2022-48899", "CVE-2022-48910", "CVE-2022-48911", "CVE-2022-48912", "CVE-2022-48924", "CVE-2022-48930", "CVE-2022-48933", "CVE-2022-48935", "CVE-2022-48937", "CVE-2023-52898", "CVE-2023-52903", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40966", "CVE-2024-41035", "CVE-2024-41042", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41098", "CVE-2024-42145", "CVE-2024-42232", "CVE-2024-42244", "CVE-2024-42265", "CVE-2024-42283", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42289", "CVE-2024-42302", "CVE-2024-42304", "CVE-2024-42305", "CVE-2024-42306", "CVE-2024-42321", "CVE-2024-42322", "CVE-2024-43828", "CVE-2024-43830", "CVE-2024-43840", "CVE-2024-43846", "CVE-2024-43853", "CVE-2024-43861", "CVE-2024-43866", "CVE-2024-43882");
  script_tag(name:"creation_date", value:"2024-11-26 04:32:11 +0000 (Tue, 26 Nov 2024)");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-22 16:37:26 +0000 (Thu, 22 Aug 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2929)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2929");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2929");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2929 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RDMA/ib_srp: Fix a deadlock(CVE-2022-48930)

netfilter: fix use-after-free in __nf_register_net_hook()(CVE-2022-48912)

protect the fetch of ->fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

io_uring: add a schedule point in io_add_buffers()(CVE-2022-48937)

ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

netfilter: nf_queue: fix possible use-after-free(CVE-2022-48911)

cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

net: ipv6: ensure we call ipv6_mc_down() at most once(CVE-2022-48910)

netfilter: nf_tables: fix memory leak during stateful obj update(CVE-2022-48933)

netfilter: nf_tables: unregister flowtable hooks on netns exit(CVE-2022-48935)

thermal: int340x: fix memory leak in int3400_notify()(CVE-2022-48924)

scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

udf: Avoid using corrupted block bitmap buffer(CVE-2024-42306)

lib: objagg: Fix general protection fault(CVE-2024-43846)

net/mlx5: Always drain health in shutdown callback(CVE-2024-43866)

exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

net: usb: qmi_wwan: fix memory leak for not ip packets(CVE-2024-43861)

io_uring: lock overflowing for IOPOLL(CVE-2023-52903)

drm/virtio: Fix GEM handle creation UAF(CVE-2022-48899)

xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

nvme: fix a possible use-after-free in controller reset during load(CVE-2022-48790)

drm/ nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes(CVE-2024-41089)

ipvs: properly dereference pe in ip_vs_add_service(CVE-2024-42322)

bpf, arm64: Fix trampoline for BPF_TRAMP_F_CALL_ORIG(CVE-2024-43840)

net: flow_dissector: use DEBUG_NET_WARN_ON_ONCE(CVE-2024-42321)

RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

tipc: Return non-zero value from tipc_udp_addr2str() on error(CVE-2024-42284)

ext4: fix infinite loop when replaying fast_commit(CVE-2024-43828)

ext4: make sure the first directory block is not a hole(CVE-2024-42304)

PCI/DPC: Fix use-after-free on concurrent DPC and hot-removal(CVE-2024-42302)

net: nexthop: Initialize all fields in dumped nexthops(CVE-2024-42283)

leds: trigger: Unregister sysfs attributes before calling deactivate()(CVE-2024-43830)

IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

NFSD: Fix ia_size underflow(CVE-2022-48828)

netfilter: nf_tables: prefer nft_chain_validate(CVE-2024-41042)

HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

tty: add the option to have a tty reject a new ldisc(CVE-2024-40966)

libceph: fix race between delayed_work() and ceph_monc_stop()(CVE-2024-42232)

ata: libata-core: Fix null pointer dereference on error(CVE-2024-41098)

USB: serial: mos7840: fix crash on ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
