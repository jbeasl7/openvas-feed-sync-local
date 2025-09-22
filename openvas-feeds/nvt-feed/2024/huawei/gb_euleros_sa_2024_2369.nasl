# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2369");
  script_cve_id("CVE-2021-46952", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47201", "CVE-2021-47236", "CVE-2021-47259", "CVE-2021-47261", "CVE-2021-47265", "CVE-2021-47277", "CVE-2021-47280", "CVE-2021-47293", "CVE-2021-47301", "CVE-2021-47311", "CVE-2021-47329", "CVE-2021-47353", "CVE-2021-47354", "CVE-2021-47373", "CVE-2021-47383", "CVE-2021-47397", "CVE-2021-47408", "CVE-2021-47416", "CVE-2021-47424", "CVE-2021-47425", "CVE-2021-47427", "CVE-2021-47435", "CVE-2021-47438", "CVE-2021-47455", "CVE-2021-47466", "CVE-2021-47469", "CVE-2021-47473", "CVE-2021-47478", "CVE-2021-47480", "CVE-2021-47483", "CVE-2021-47495", "CVE-2021-47497", "CVE-2021-47501", "CVE-2021-47516", "CVE-2021-47527", "CVE-2021-47541", "CVE-2021-47544", "CVE-2021-47548", "CVE-2021-47565", "CVE-2021-47566", "CVE-2021-47576", "CVE-2021-47579", "CVE-2021-47588", "CVE-2021-47589", "CVE-2021-47597", "CVE-2021-47606", "CVE-2021-47609", "CVE-2021-47619", "CVE-2022-48695", "CVE-2022-48715", "CVE-2022-48742", "CVE-2022-48744", "CVE-2022-48754", "CVE-2022-48786", "CVE-2022-48799", "CVE-2022-48804", "CVE-2022-48809", "CVE-2022-48810", "CVE-2022-48855", "CVE-2023-52478", "CVE-2023-52653", "CVE-2023-52679", "CVE-2023-52698", "CVE-2023-52703", "CVE-2023-52708", "CVE-2023-52739", "CVE-2023-52752", "CVE-2023-52796", "CVE-2023-52803", "CVE-2023-52813", "CVE-2023-52835", "CVE-2023-52843", "CVE-2023-52868", "CVE-2023-52881", "CVE-2024-26633", "CVE-2024-26641", "CVE-2024-26846", "CVE-2024-26880", "CVE-2024-26883", "CVE-2024-27020", "CVE-2024-27062", "CVE-2024-27388", "CVE-2024-35789", "CVE-2024-35805", "CVE-2024-35807", "CVE-2024-35808", "CVE-2024-35809", "CVE-2024-35815", "CVE-2024-35823", "CVE-2024-35835", "CVE-2024-35847", "CVE-2024-35886", "CVE-2024-35888", "CVE-2024-35896", "CVE-2024-35904", "CVE-2024-35910", "CVE-2024-35922", "CVE-2024-35925", "CVE-2024-35930", "CVE-2024-35955", "CVE-2024-35960", "CVE-2024-35962", "CVE-2024-35969", "CVE-2024-35984", "CVE-2024-35995", "CVE-2024-35997", "CVE-2024-36004", "CVE-2024-36016", "CVE-2024-36883", "CVE-2024-36901", "CVE-2024-36902", "CVE-2024-36903", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36917", "CVE-2024-36919", "CVE-2024-36924", "CVE-2024-36940", "CVE-2024-36952", "CVE-2024-36971", "CVE-2024-37353", "CVE-2024-37356", "CVE-2024-38538", "CVE-2024-38541", "CVE-2024-38559", "CVE-2024-38588", "CVE-2024-38596", "CVE-2024-38601", "CVE-2024-39276", "CVE-2024-39480", "CVE-2024-39487", "CVE-2024-40904", "CVE-2024-40960", "CVE-2024-40984", "CVE-2024-40995", "CVE-2024-40998", "CVE-2024-41005", "CVE-2024-41007");
  script_tag(name:"creation_date", value:"2024-09-12 08:10:51 +0000 (Thu, 12 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 18:01:33 +0000 (Mon, 08 Jul 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2369");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2369");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel:ACPI: CPPC: Use access_width over bit_width for system memory accesses(CVE-2024-35995)

kernel: block: fix overflow in blk_ioctl_discard()(CVE-2024-36917)

kernel:block: prevent division by zero in blk_rq_stat_sum()(CVE-2024-35925)

bpf: Fix stackmap overflow check on 32-bit arches(CVE-2024-26883)

kernel:calipso: fix memory leak in netlbl_calipso_add_pass()(CVE-2023-52698)

kernel:erspan: make sure erspan_base_hdr is present in skb->head(CVE-2024-35888)

kernel: ext4: fix corruption during on-line resize(CVE-2024-35807)

kernel:HID: i2c-hid: remove I2C_HID_READ_PENDING flag to prevent lock-up(CVE-2024-35997)

HID: logitech-hidpp: Fix kernel crash on receiver USB disconnect(CVE-2023-52478)

kernel:i2c: smbus: fix NULL function pointer dereference(CVE-2024-35984)

kernel:i40e: Do not use WQ_MEM_RECLAIM flag for workqueue(CVE-2024-36004)

i40e: Fix NULL ptr dereference on VSI filter sync(CVE-2021-47184)

iavf: free q_vectors before queues in iavf_disable_vf(CVE-2021-47201)

ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim()(CVE-2024-26633)

ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv()(CVE-2024-26641)

kernel:ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action()(CVE-2024-36902)

kernel:ipv6: Fix infinite recursion in fib6_dump_done().(CVE-2024-35886)

kernel:ipv6: Fix potential uninit-value access in __ip6_make_skb()(CVE-2024-36903)

kernel:ipv6: prevent NULL dereference in ip6_output()(CVE-2024-36901)

kernel:ipvlan: add ipvlan_route_v6_outbound() helper(CVE-2023-52796)

kernel:irqchip/gic-v3-its: Prevent double free on error(CVE-2024-35847)

kernel: md/dm-raid: don&#39,t call md_reap_sync_thread() directly(CVE-2024-35808)

kernel:net/mlx5: Properly link new fs rules into the tree(CVE-2024-35960)

kernel:net/mlx5e: fix a double-free in arfs_create_groups(CVE-2024-35835)

kernel:net: fix __dst_negative_advice() race(CVE-2024-36971)

kernel:net: fix out-of-bounds access in ops_init(CVE-2024-36883)

kernel:netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get()(CVE-2024-27020)

kernel:netfilter: validate user input for expected length(CVE-2024-35896)

NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds(CVE-2021-46952)

kernel:nvme-fc: do not wait in vain when unloading module(CVE-2024-26846)

nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells(CVE-2021-47497)

kernel: PCI/PM: Drain runtime-idle callbacks before driver removal(CVE-2024-35809)

kernel: perf/core: Bail out early if the request AUX area is out of bound(CVE-2023-52835)

kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

kernel:dm: call the resume method on internal suspend(CVE-2024-26880)

kernel:RDMA: Verify port when creating flow rule(CVE-2021-47265)

kernel:ring-buffer: Fix a race between readers and resize checks(CVE-2024-38601)

kernel: scsi: bnx2fc: Remove spin_lock_bh while ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h1335.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h1335.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h1335.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h1335.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
