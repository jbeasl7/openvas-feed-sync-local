# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1521");
  script_cve_id("CVE-2022-49052", "CVE-2022-49053", "CVE-2022-49114", "CVE-2022-49308", "CVE-2022-49341", "CVE-2022-49414", "CVE-2022-49447", "CVE-2022-49526", "CVE-2022-49720", "CVE-2023-52572", "CVE-2024-53124", "CVE-2024-53173", "CVE-2024-53217", "CVE-2024-56606", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56780", "CVE-2024-57883", "CVE-2025-21648", "CVE-2025-21687", "CVE-2025-21731");
  script_tag(name:"creation_date", value:"2025-05-13 04:28:55 +0000 (Tue, 13 May 2025)");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-21 16:49:03 +0000 (Fri, 21 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1521");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1521");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cifs: Fix UAF in cifs_demultiplex_thread().(CVE-2023-52572)

net: fix data-races around sk->sk_forward_alloc(CVE-2024-53124)

quota: flush quota_release_work upon quota writeback(CVE-2024-56780)

af_packet: avoid erroring out after sock_init_data() in packet_create().(CVE-2024-56606)

net: defer final 'struct net' free in netns dismantle(CVE-2024-56658)

netfilter: x_tables: fix LED ID check in led_tg_check().(CVE-2024-56650)

mm: hugetlb: independent PMD page table shared count(CVE-2024-57883)

NFSv4.0: Fix a use-after-free problem in the asynchronous open()(CVE-2024-53173)

NFSD: Prevent NULL dereference in nfsd4_process_cb_update()(CVE-2024-53217)

netfilter: conntrack: clamp maximum hashtable size to INT_MAX(CVE-2025-21648)

vfio/platform: check the bounds of read/write syscalls(CVE-2025-21687)

mm: fix unexpected zeroed page mapping with zram swap(CVE-2022-49052)

ext4: fix race condition between ext4_write and ext4_convert_inline_data(CVE-2022-49414)

block: Fix handling of offline queues in blk_mq_alloc_request_hctx().(CVE-2022-49720)

scsi: libfc: Fix use after free in fc_exch_abts_resp().(CVE-2022-49114)

nbd: don't allow reconnect after disconnect(CVE-2025-21731)

md/bitmap: don't set sb values if can't pass sanity check(CVE-2022-49526)

ARM: hisi: Add missing of_node_put after of_find_compatible_node(CVE-2022-49447)

bpf, arm64: Clear prog->jited_len along prog->jited(CVE-2022-49341)

extcon: Modify extcon device to be created after driver data is set(CVE-2022-49308)

scsi: target: tcmu: Fix possible page UAF(CVE-2022-49053)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2003.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h2003.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2003.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2003.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h2003.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
