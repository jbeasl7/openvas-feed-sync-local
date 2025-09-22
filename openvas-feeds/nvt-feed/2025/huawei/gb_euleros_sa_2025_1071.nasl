# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1071");
  script_cve_id("CVE-2021-47391", "CVE-2022-48724", "CVE-2022-48732", "CVE-2022-48789", "CVE-2022-48790", "CVE-2022-48796", "CVE-2022-48828", "CVE-2022-48834", "CVE-2022-48836", "CVE-2022-48850", "CVE-2022-48899", "CVE-2022-48910", "CVE-2022-48911", "CVE-2022-48912", "CVE-2022-48924", "CVE-2022-48930", "CVE-2022-48933", "CVE-2022-48935", "CVE-2022-48937", "CVE-2023-52696", "CVE-2023-52742", "CVE-2023-52898", "CVE-2023-52903", "CVE-2024-23848", "CVE-2024-26881", "CVE-2024-26891", "CVE-2024-27047", "CVE-2024-35801", "CVE-2024-35878", "CVE-2024-35884", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-38659", "CVE-2024-39482", "CVE-2024-39494", "CVE-2024-39497", "CVE-2024-39501", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40947", "CVE-2024-40953", "CVE-2024-40966", "CVE-2024-41002", "CVE-2024-41012", "CVE-2024-41013", "CVE-2024-41014", "CVE-2024-41020", "CVE-2024-41023", "CVE-2024-41027", "CVE-2024-41035", "CVE-2024-41041", "CVE-2024-41042", "CVE-2024-41044", "CVE-2024-41048", "CVE-2024-41049", "CVE-2024-41050", "CVE-2024-41051", "CVE-2024-41069", "CVE-2024-41074", "CVE-2024-41075", "CVE-2024-41077", "CVE-2024-41079", "CVE-2024-41080", "CVE-2024-41082", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41090", "CVE-2024-41091", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-41098", "CVE-2024-42067", "CVE-2024-42068", "CVE-2024-42070", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42084", "CVE-2024-42090", "CVE-2024-42096", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42106", "CVE-2024-42124", "CVE-2024-42131", "CVE-2024-42145", "CVE-2024-42147", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42154", "CVE-2024-42161", "CVE-2024-42223", "CVE-2024-42229", "CVE-2024-42232", "CVE-2024-42244", "CVE-2024-42246", "CVE-2024-42265", "CVE-2024-42283", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42289", "CVE-2024-42302", "CVE-2024-42304", "CVE-2024-42305", "CVE-2024-42306", "CVE-2024-42321", "CVE-2024-42322", "CVE-2024-43828", "CVE-2024-43830", "CVE-2024-43840", "CVE-2024-43846", "CVE-2024-43853", "CVE-2024-43861", "CVE-2024-43866", "CVE-2024-43882");
  script_tag(name:"creation_date", value:"2025-02-05 04:31:15 +0000 (Wed, 05 Feb 2025)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-22 16:37:26 +0000 (Thu, 22 Aug 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1071");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1071");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ASoC: topology: Fix references to freed memory(CVE-2024-41069)

bcache: fix variable length array abuse in btree_iter(CVE-2024-39482)

bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

bpf: Avoid uninitialized value in BPF_CORE_READ_BITFIELD(CVE-2024-42161)

bpf: Take return from set_memory_ro() into account with bpf_prog_lock_ro(CVE-2024-42068)

bpf: Take return from set_memory_rox() into account with bpf_jit_binary_lock_ro(CVE-2024-42067)

cachefiles: add consistency check for copen/cread(CVE-2024-41075)

cachefiles: cyclic allocation of msg_id to avoid reuse(CVE-2024-41050)

cachefiles: Set object to close if ondemand_id < 0 in copen(CVE-2024-41074)

cachefiles: wait for ondemand_object_worker to finish when dropping object(CVE-2024-41051)

crypto: aead,cipher - zeroize key buffer after use(CVE-2024-42229)

crypto: ecdh - explicitly zeroize private_key(CVE-2024-42098)

crypto: hisilicon/debugfs - Fix debugfs uninit process issue(CVE-2024-42147)

crypto: hisilicon/sec - Fix memory leak for sec resource release(CVE-2024-41002)

drivers: core: synchronize really_probe() and dev_uevent(CVE-2024-39501)

drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes(CVE-2024-41095)

drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes(CVE-2024-42101)

drm/nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

drm/shmem-helper: Fix BUG_ON() on mmap(PROT_WRITE, MAP_PRIVATE)(CVE-2024-39497)

enic: Validate length of nl attributes in enic_set_vf_port(CVE-2024-38659)

filelock: Fix fcntl/close race recovery compat path(CVE-2024-41020)

filelock: fix potential use-after-free in posix_lock_inode(CVE-2024-41049)

filelock: Remove locks reliably when fcntl/close race is detected(CVE-2024-41012)

Fix userfaultfd_api to return EINVAL as expected(CVE-2024-41027)

ftruncate: pass a signed offset(CVE-2024-42084)

ima: Avoid blocking in RCU read-side critical section(CVE-2024-40947)

In the Linux kernel through 6.7.1, there is a use-after-free in cec_queue_msg_fh, related to drivers/media/cec/core/cec-adap.c and drivers/media/cec/core/cec-api.c.(CVE-2024-23848)

inet_diag: Initialize pad field in struct inet_diag_req_v2(CVE-2024-42106)

Input: aiptek - properly check endpoint type(CVE-2022-48836)

io_uring: fix possible deadlock in io_register_iowq_max_workers()(CVE-2024-41080)

iommu/vt-d: Don't issue ATS Invalidation request when device is disconnected(CVE-2024-26891)

iommu/vt-d: Fix potential memory leak in intel_setup_irq_remapping()(CVE-2022-48724)

iommu: Fix potential use-after-free during probe(CVE-2022-48796)

kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

kernel:RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests(CVE-2021-47391)

KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin(CVE-2024-40953)

media: dvb-frontends: tda10048: Fix integer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2177.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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
