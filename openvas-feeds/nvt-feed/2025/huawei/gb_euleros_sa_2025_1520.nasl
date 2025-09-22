# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1520");
  script_cve_id("CVE-2021-47634", "CVE-2021-47659", "CVE-2022-49052", "CVE-2022-49053", "CVE-2022-49114", "CVE-2022-49155", "CVE-2022-49259", "CVE-2022-49264", "CVE-2022-49280", "CVE-2022-49307", "CVE-2022-49316", "CVE-2022-49341", "CVE-2022-49370", "CVE-2022-49385", "CVE-2022-49388", "CVE-2022-49395", "CVE-2022-49404", "CVE-2022-49407", "CVE-2022-49414", "CVE-2022-49433", "CVE-2022-49441", "CVE-2022-49447", "CVE-2022-49450", "CVE-2022-49478", "CVE-2022-49526", "CVE-2022-49532", "CVE-2022-49535", "CVE-2022-49538", "CVE-2022-49564", "CVE-2022-49581", "CVE-2022-49620", "CVE-2022-49647", "CVE-2022-49674", "CVE-2022-49687", "CVE-2022-49731", "CVE-2023-52572", "CVE-2024-56606", "CVE-2024-56614", "CVE-2024-56658", "CVE-2024-56780", "CVE-2024-57883", "CVE-2024-57931", "CVE-2024-57977", "CVE-2024-57980", "CVE-2024-57996", "CVE-2025-21648", "CVE-2025-21700", "CVE-2025-21702", "CVE-2025-21719", "CVE-2025-21731", "CVE-2025-21791", "CVE-2025-21796", "CVE-2025-21806", "CVE-2025-21858");
  script_tag(name:"creation_date", value:"2025-05-13 04:28:55 +0000 (Tue, 13 May 2025)");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-12 14:15:15 +0000 (Wed, 12 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1520)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1520");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1520");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1520 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cifs: Fix UAF in cifs_demultiplex_thread().(CVE-2023-52572)

xsk: fix OOB map writes when deleting elements(CVE-2024-56614)

net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

selinux: ignore unknown extended permissions(CVE-2024-57931)

netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21700)

net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21702)

ubi: Fix race condition between ctrl_cdev_ioctl and ubi_cdev_ioctl(CVE-2021-47634)

crypto: qat - add param check for DH(CVE-2022-49564)

nfsd: clear acl_access/acl_default after releasing them(CVE-2025-21796)

media: uvcvideo: Fix double free in error path(CVE-2024-57980)

ata: libata-core: fix NULL pointer deref in ata_host_alloc_pinfo().(CVE-2022-49731)

dm raid: fix accesses beyond end of raid member array(CVE-2022-49674)

scsi: lpfc: Fix null pointer dereference after failing to issue FLOGI and PLOGI(CVE-2022-49535)

md/bitmap: don't set sb values if can't pass sanity check(CVE-2022-49526)

drm/virtio: fix NULL pointer dereference in virtio_gpu_conn_get_modes(CVE-2022-49532)

ext4: fix race condition between ext4_write and ext4_convert_inline_data(CVE-2022-49414)

media: pvrusb2: fix array-index-out-of-bounds in pvr2_i2c_core_init(CVE-2022-49478)

dlm: fix plock invalid read(CVE-2022-49407)

NFSD: prevent underflow in nfssvc_decode_writeargs().(CVE-2022-49280)

NFSv4: Don't hold the layoutget locks across multiple RPC calls(CVE-2022-49316)

firmware: dmi-sysfs: Fix memory leak in dmi_sysfs_register_handle(CVE-2022-49370)

ARM: hisi: Add missing of_node_put after of_find_compatible_node(CVE-2022-49447)

scsi: target: tcmu: Fix possible page UAF(CVE-2022-49053)

drm/plane: Move range check for format_count earlier(CVE-2021-47659)

tty: fix deadlock caused by calling printk() under tty_port->lock(CVE-2022-49441)

bpf, arm64: Clear prog->jited_len along prog->jited(CVE-2022-49341)

RDMA/hfi1: Fix potential integer multiplication overflow errors(CVE-2022-49404)

scsi: libfc: Fix use after free in fc_exch_abts_resp().(CVE-2022-49114)

scsi: qla2xxx: Suppress a kernel complaint in qla_create_qpair().(CVE-2022-49155)

mm: fix unexpected zeroed page mapping with zram swap(CVE-2022-49052)

net: tipc: fix possible refcount leak in tipc_sk_create()(CVE-2022-49620)

RDMA/hfi1: Prevent use of lock before it is initialized(CVE-2022-49433)

memcg: fix soft lockup in the OOM process(CVE-2024-57977)

block: don't delete queue kobject before its children(CVE-2022-49259)

exec: Force single empty string when argv is empty(CVE-2022-49264)

um: Fix ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1824.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1824.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1824.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1824.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1824.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
