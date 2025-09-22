# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1140");
  script_cve_id("CVE-2022-48868", "CVE-2022-48916", "CVE-2022-48961", "CVE-2022-48975", "CVE-2023-52917", "CVE-2023-52920", "CVE-2024-43817", "CVE-2024-44958", "CVE-2024-46678", "CVE-2024-46714", "CVE-2024-46765", "CVE-2024-46830", "CVE-2024-47668", "CVE-2024-47674", "CVE-2024-47678", "CVE-2024-47679", "CVE-2024-47684", "CVE-2024-47692", "CVE-2024-47693", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47701", "CVE-2024-47705", "CVE-2024-47707", "CVE-2024-47710", "CVE-2024-47728", "CVE-2024-47730", "CVE-2024-47737", "CVE-2024-47739", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-47749", "CVE-2024-49851", "CVE-2024-49856", "CVE-2024-49858", "CVE-2024-49861", "CVE-2024-49863", "CVE-2024-49875", "CVE-2024-49878", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49886", "CVE-2024-49889", "CVE-2024-49891", "CVE-2024-49899", "CVE-2024-49906", "CVE-2024-49907", "CVE-2024-49925", "CVE-2024-49927", "CVE-2024-49933", "CVE-2024-49934", "CVE-2024-49935", "CVE-2024-49940", "CVE-2024-49944", "CVE-2024-49948", "CVE-2024-49949", "CVE-2024-49952", "CVE-2024-49954", "CVE-2024-49955", "CVE-2024-49959", "CVE-2024-49960", "CVE-2024-49974", "CVE-2024-49975", "CVE-2024-49978", "CVE-2024-49983", "CVE-2024-49995", "CVE-2024-50001", "CVE-2024-50002", "CVE-2024-50006", "CVE-2024-50014", "CVE-2024-50015", "CVE-2024-50016", "CVE-2024-50024", "CVE-2024-50028", "CVE-2024-50033", "CVE-2024-50038", "CVE-2024-50039", "CVE-2024-50040", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50047", "CVE-2024-50058", "CVE-2024-50060", "CVE-2024-50063", "CVE-2024-50067", "CVE-2024-50072", "CVE-2024-50073", "CVE-2024-50074", "CVE-2024-50082", "CVE-2024-50095", "CVE-2024-50099", "CVE-2024-50115", "CVE-2024-50131", "CVE-2024-50135", "CVE-2024-50138", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50154", "CVE-2024-50167", "CVE-2024-50179", "CVE-2024-50192", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50208", "CVE-2024-50209", "CVE-2024-50241", "CVE-2024-50251", "CVE-2024-50256", "CVE-2024-50258", "CVE-2024-50262", "CVE-2024-50264", "CVE-2024-50267", "CVE-2024-50272", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-50289", "CVE-2024-50296", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-50304", "CVE-2024-53052", "CVE-2024-53057", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53073", "CVE-2024-53079", "CVE-2024-53085", "CVE-2024-53088", "CVE-2024-53095", "CVE-2024-53096", "CVE-2024-53099", "CVE-2024-53104", "CVE-2024-53119", "CVE-2024-53121", "CVE-2024-53141", "CVE-2024-53142");
  script_tag(name:"creation_date", value:"2025-02-10 09:04:52 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-11T05:38:07+0000");
  script_tag(name:"last_modification", value:"2025-02-11 05:38:07 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 19:17:56 +0000 (Tue, 10 Dec 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1140");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1140");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"bonding: change ipsec_lock from spin lock to mutex(CVE-2024-46678)

ice: protect XDP configuration with a mutex(CVE-2024-46765)

sched/smt: Fix unbalance sched_smt_present dec/inc(CVE-2024-44958)

mm: avoid leaving partial pfn mappings around in error case(CVE-2024-47674)

blk_iocost: fix more out of bound shifts(CVE-2024-49933)

x86/ioapic: Handle allocation failures gracefully(CVE-2024-49927)

In the Linux kernel, the following vulnerability has been resolved:ntb: intel: Fix the NULL vs IS_ERR() bug for debugfs_create_dir() The debugfs_create_dir() function returns error pointers. It never returns NULL. So use IS_ERR() to check it.(CVE-2023-52917)

mm: call the security_mmap_file() LSM hook in remap_file_pages().(CVE-2024-47745)

ext4: avoid use-after-free in ext4_ext_show_leaf().(CVE-2024-49889)

tpm: Clean up TPM space after command failure(CVE-2024-49851)

sock_map: Add a cond_resched() in sock_hash_free().(CVE-2024-47710)

tcp: check skb is non-NULL in tcp_rto_delta_us().(CVE-2024-47684)

ext4: avoid OOB when system.data xattr changes underneath the filesystem(CVE-2024-47701)

ext4: fix double brelse() the buffer of the extents path(CVE-2024-49882)

fbdev: efifb: Register sysfs groups through driver core(CVE-2024-49925)

ext4: fix slab-use-after-free in ext4_split_extent_at().(CVE-2024-49884)

ext4: aovid use-after-free in ext4_ext_insert_extent().(CVE-2024-49883)

ACPI: PAD: fix crash in exit_round_robin().(CVE-2024-49935)

ext4: update orig_path in ext4_find_extent().(CVE-2024-49881)

padata: use integer wrap around to prevent deadlock on seq_nr overflow(CVE-2024-47739)

drm/amd/display: Check null pointer before try to access it(CVE-2024-49906)

netfilter: xtables: avoid NFPROTO_UNSPEC where needed(CVE-2024-50038)

drm/amd/display: Check null pointers before using dc->clk_mgr(CVE-2024-49907)

drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error(CVE-2024-47697)

uprobes: fix kernel info leak via '[uprobes]' vma(CVE-2024-49975)

ext4: dax: fix overflowing extents beyond inode size when partially writing(CVE-2024-50015)

net/sched: accept TCA_STAB only for root qdisc(CVE-2024-50039)

block: fix potential invalid pointer dereference in blk_add_partition(CVE-2024-47705)

nfsd: map the EBADMSG to nfserr_io to avoid warning(CVE-2024-49875)

vhost/scsi: null-ptr-dereference in vhost_scsi_get_req().(CVE-2024-49863)

thermal: core: Reference count the zone in thermal_zone_get_by_id().(CVE-2024-50028)

bpf: Zero former ARG_PTR_TO_{LONG,INT} args in case of error(CVE-2024-47728)

net: mdio: fix unbalanced fwnode reference count in mdio_device_release().(CVE-2022-48961)

IB/core: Fix ib_cache_setup_one error flow cleanup(CVE-2024-47693)

bpf: Fix helper writes to read-only maps(CVE-2024-49861)

nfsd: return -EINVAL when namelen is 0(CVE-2024-47692)

gpiolib: fix memory leak in gpiochip_setup_dev().(CVE-2022-48975)

RDMA/cxgb4: Added NULL check for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1765.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
