# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1957");
  script_cve_id("CVE-2022-49072", "CVE-2022-49267", "CVE-2022-49579", "CVE-2022-49722", "CVE-2022-49837", "CVE-2022-49889", "CVE-2023-53001", "CVE-2023-53091", "CVE-2023-53093", "CVE-2023-53137", "CVE-2023-53146", "CVE-2024-50019", "CVE-2024-57951", "CVE-2024-57982", "CVE-2024-58237", "CVE-2025-21703", "CVE-2025-21750", "CVE-2025-21844", "CVE-2025-21891", "CVE-2025-21922", "CVE-2025-21975", "CVE-2025-21981", "CVE-2025-22005", "CVE-2025-22026", "CVE-2025-22027", "CVE-2025-22058", "CVE-2025-22063", "CVE-2025-22090", "CVE-2025-22113", "CVE-2025-22121", "CVE-2025-23131", "CVE-2025-23136", "CVE-2025-23149", "CVE-2025-23150", "CVE-2025-37738", "CVE-2025-37752", "CVE-2025-37785", "CVE-2025-37807", "CVE-2025-37808", "CVE-2025-37839", "CVE-2025-37867", "CVE-2025-37911", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37930", "CVE-2025-37940", "CVE-2025-37995", "CVE-2025-39728");
  script_tag(name:"creation_date", value:"2025-08-12 04:32:34 +0000 (Tue, 12 Aug 2025)");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 15:57:18 +0000 (Fri, 14 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1957)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1957");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1957");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1957 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gpio: Restrict usage of GPIO chip irq members before initialization(CVE-2022-49072)

mmc: core: use sysfs_emit() instead of sprintf().(CVE-2022-49267)

ipv4: Fix data-races around sysctl_fib_multipath_hash_policy.(CVE-2022-49579)

ice: Fix memory corruption in VF driver(CVE-2022-49722)

bpf: Fix memory leaks in __check_func_call(CVE-2022-49837)

ring-buffer: Check for NULL cpu_buffer in ring_buffer_wake_waiters().(CVE-2022-49889)

drm/drm_vma_manager: Add drm_vma_node_allow_once().(CVE-2023-53001)

ext4: update s_journal_inum if it changes after journal replay(CVE-2023-53091)

tracing: Do not let histogram values have some modifiers(CVE-2023-53093)

ext4: Fix possible corruption when moving a directory(CVE-2023-53137)

media: dw2102: Fix null-ptr-deref in dw2102_i2c_transfer().(CVE-2023-53146)

kthread: unpark only parked kthread(CVE-2024-50019)

hrtimers: Handle CPU state correctly on hotplug(CVE-2024-57951)

xfrm: state: fix out-of-bounds read during lookup(CVE-2024-57982)

bpf: consider that tail calls invalidate packet pointers(CVE-2024-58237)

netem: Update sch->q.qlen before qdisc_tree_reduce_backlog().(CVE-2025-21703)

wifi: brcmfmac: Check the return value of of_property_read_string_index().(CVE-2025-21750)

smb: client: Add check for next_buffer in receive_encrypted_standard().(CVE-2025-21844)

ipvlan: ensure network headers are in skb linear part(CVE-2025-21891)

ppp: Fix KMSAN uninit-value warning with bpf(CVE-2025-21922)

net/mlx5: handle errors in mlx5_chains_create_table().(CVE-2025-21975)

ice: fix memory leak in aRFS after reset(CVE-2025-21981)

ipv6: Fix memleak of nhc_pcpu_rth_output in fib_check_nh_v6_gw().(CVE-2025-22005)

nfsd: don't ignore the return code of svc_proc_register().(CVE-2025-22026)

media: streamzap: fix race between device disconnection and urb callback(CVE-2025-22027)

udp: Fix memory accounting leak.(CVE-2025-22058)

netlabel: Fix NULL pointer exception caused by CALIPSO on IPv4 sockets.(CVE-2025-22063)

x86/mm/pat: Fix VM_PAT handling when fork() fails in copy_page_range().(CVE-2025-22090)

ext4: avoid journaling sb update on error if journal is destroying(CVE-2025-22113)

ext4: fix out-of-bound read in ext4_xattr_inode_dec_ref_all().(CVE-2025-22121)

dlm: prevent NPD when writing a positive value to event_done(CVE-2025-23131)

thermal: int340x: Add NULL check for adev(CVE-2025-23136)

tpm: do not start chip while suspended(CVE-2025-23149)

ext4: fix off-by-one error in do_split(CVE-2025-23150)

ext4: ignore xattrs past end(CVE-2025-37738)

net_sched: sch_sfq: move the limit validation(CVE-2025-37752)

ext4: fix OOB read when checking dotdot dir(CVE-2025-37785)

bpf: Fix kmemleak warning for percpu hashmap(CVE-2025-37807)

crypto: null - Use spin lock instead of mutex(CVE-2025-37808)

jbd2: remove wrong sb->s_sequence check(CVE-2025-37839)

RDMA/core: Silence oversized kvmalloc() warning(CVE-2025-37867)

bnxt_en: Fix out-of-bound ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1941.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
