# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2907");
  script_cve_id("CVE-2021-47296", "CVE-2021-47356", "CVE-2021-47408", "CVE-2022-48863", "CVE-2022-48924", "CVE-2022-48930", "CVE-2022-48943", "CVE-2023-52885", "CVE-2023-52898", "CVE-2023-52915", "CVE-2024-38659", "CVE-2024-39509", "CVE-2024-40953", "CVE-2024-40959", "CVE-2024-41012", "CVE-2024-41014", "CVE-2024-41020", "CVE-2024-41035", "CVE-2024-41041", "CVE-2024-41044", "CVE-2024-41069", "CVE-2024-41087", "CVE-2024-41090", "CVE-2024-41091", "CVE-2024-42070", "CVE-2024-42084", "CVE-2024-42096", "CVE-2024-42102", "CVE-2024-42131", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42154", "CVE-2024-42223", "CVE-2024-42229", "CVE-2024-42232", "CVE-2024-42265", "CVE-2024-42280", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42288", "CVE-2024-42289", "CVE-2024-42292", "CVE-2024-42301", "CVE-2024-42305", "CVE-2024-42312", "CVE-2024-43853", "CVE-2024-43856", "CVE-2024-43871", "CVE-2024-43882", "CVE-2024-43890", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43900", "CVE-2024-43914", "CVE-2024-44948", "CVE-2024-44987", "CVE-2024-45006", "CVE-2024-46738", "CVE-2024-46800");
  script_tag(name:"creation_date", value:"2024-11-11 04:32:03 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 17:18:55 +0000 (Fri, 20 Sep 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2907)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2907");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2907");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2907 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SUNRPC: Fix UAF in svc_tcp_listen_data_ready()(CVE-2023-52885)

HID: core: remove unnecessary WARN_ON() in implement()(CVE-2024-39509)

xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

x86: stop playing stack games in profile_pc()(CVE-2024-42096)

ASoC: topology: Fix references to freed memory(CVE-2024-41069)

crypto: aead,cipher - zeroize key buffer after use(CVE-2024-42229)

ata: libata-core: Fix double free on error(CVE-2024-41087)

media: dvb-frontends: tda10048: Fix integer overflow(CVE-2024-42223)

xfs: add bounds checking to xlog_recover_process_data(CVE-2024-41014)

USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor(CVE-2024-41035)

ftruncate: pass a signed offset(CVE-2024-42084)

filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

thermal: int340x: fix memory leak in int3400_notify()(CVE-2022-48924)

ext4: check dot and dotdot of dx_root before making dir indexed(CVE-2024-42305)

scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

scsi: qla2xxx: Fix for possible memory corruption(CVE-2024-42288)

exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

xhci: Fix null pointer dereference when host dies(CVE-2023-52898)

dev/parport: fix the array out-of-bounds risk(CVE-2024-42301)

mm: avoid overflows in dirty throttling logic(CVE-2024-42131)

IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

tipc: Return non-zero value from tipc_udp_addr2str() on error(CVE-2024-42284)

netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers(CVE-2024-42070)

bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

libceph: fix race between delayed_work() and ceph_monc_stop()(CVE-2024-42232)

mISDN: Fix a use after free in hfcmulti_tx()(CVE-2024-42280)

cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

protect the fetch of ->fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

KVM: PPC: Fix kvm_arch_vcpu_ioctl vcpu_load leak(CVE-2021-47296)

KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin()(CVE-2024-40953)

KVM: x86/mmu: make apf token non-zero to fix bug(CVE-2022-48943)

udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port().(CVE-2024-41041)

ppp: reject claimed-as-LCP but actually malformed packets(CVE-2024-41044)

enic: Validate length of nl attributes in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1720.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1720.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1720.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1720.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1720.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
