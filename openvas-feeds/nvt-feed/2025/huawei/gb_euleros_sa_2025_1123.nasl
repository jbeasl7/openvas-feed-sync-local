# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1123");
  script_cve_id("CVE-2021-47261", "CVE-2021-47274", "CVE-2021-47311", "CVE-2021-47354", "CVE-2021-47378", "CVE-2021-47391", "CVE-2021-47456", "CVE-2021-47483", "CVE-2021-47496", "CVE-2021-47497", "CVE-2021-47541", "CVE-2021-47548", "CVE-2021-47576", "CVE-2021-47589", "CVE-2022-48732", "CVE-2022-48742", "CVE-2022-48754", "CVE-2022-48788", "CVE-2022-48855", "CVE-2022-48912", "CVE-2023-52832", "CVE-2023-52880", "CVE-2023-52881", "CVE-2023-52885", "CVE-2024-26852", "CVE-2024-26865", "CVE-2024-26923", "CVE-2024-26934", "CVE-2024-26976", "CVE-2024-35789", "CVE-2024-35950", "CVE-2024-35955", "CVE-2024-35960", "CVE-2024-36016", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36940", "CVE-2024-36971", "CVE-2024-38538", "CVE-2024-38541", "CVE-2024-38559", "CVE-2024-38588", "CVE-2024-39480", "CVE-2024-39487", "CVE-2024-41087", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42154", "CVE-2024-42228", "CVE-2024-42285", "CVE-2024-43882", "CVE-2024-44987", "CVE-2024-46673", "CVE-2024-46722", "CVE-2024-46723", "CVE-2024-46743", "CVE-2024-46744", "CVE-2024-46756", "CVE-2024-46757", "CVE-2024-46758", "CVE-2024-46759", "CVE-2024-46800", "CVE-2024-46816", "CVE-2024-47685");
  script_tag(name:"creation_date", value:"2025-01-21 04:31:06 +0000 (Tue, 21 Jan 2025)");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1123");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1123");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel: drm/sched: Avoid data corruptions(CVE-2021-47354)

drm/sched: Avoid data corruptions(CVE-2024-46759)

hwmon: (lm95234) Fix underflows seen when writing limit attributes(CVE-2024-46758)

exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

Squashfs: sanity check symbolic link size(CVE-2024-46744)

scsi: aacraid: Fix double-free on probe failure(CVE-2024-46673)

ata: libata-core: Fix double free on error(CVE-2024-41087)

drm/amdgpu: fix ucode out-of-bounds read warning(CVE-2024-46723)

tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

drm/amdgpu: fix ucode out-of-bounds read warning(CVE-2024-42228)

hwmon: (nct6775-core) Fix underflows seen when writing limit attributes(CVE-2024-46757)

kernel:scsi: qedf: Ensure the copied buf is NUL terminated(CVE-2024-38559)

drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links(CVE-2024-46816)

of/irq: Prevent device address out-of-bounds read in interrupt map walk(CVE-2024-46743)

net/tls: Fix flipped sign in tls_err_abort() calls(CVE-2021-47496)

netfilter: fix use-after-free in __nf_register_net_hook()(CVE-2022-48912)

SUNRPC: Fix UAF in svc_tcp_listen_data_ready()(CVE-2023-52885)

drm/ nouveau: fix off by one in BIOS boundary checking(CVE-2022-48732)

kernel:RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests(CVE-2021-47391)

kernel:sctp: fix kernel-infoleak for SCTP sockets(CVE-2022-48855)

igbvf: fix double free in `igbvf_probe`(CVE-2021-47589)

rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()(CVE-2022-48742)

phylib: fix potential use-after-free(CVE-2022-48754)

kernel:net: qcom/emac: fix UAF in emac_remove(CVE-2021-47311)

kernel:tcp: do not accept ACK of bytes we never sent(CVE-2023-52881)

kernel:net/mlx4_en: Fix an use-after-free bug in mlx4_en_try_alloc_resources()(CVE-2021-47541)

net/ipv6: avoid possible UAF in ip6_route_mpath_notify()(CVE-2024-26852)

kernel:tty: n_gsm: fix possible out-of-bounds in gsm0_receive()(CVE-2024-36016)

kernel:tcp: Use refcount_inc_not_zero() in tcp_twsk_unique().(CVE-2024-36904)

kernel: pinctrl: core: delete incorrect free in pinctrl_enable()(CVE-2024-36940)

drm/client: Fully protect modes[] with dev->mode_config.mutex(CVE-2024-35950)

USB: core: Fix deadlock in usb_deauthorize_interface()(CVE-2024-26934)

KVM: Always flush async #PF workqueue when vCPU is being destroyed(CVE-2024-26976)

sch/ netem: fix use after free in netem_dequeue(CVE-2024-46800)

ipv6: prevent UAF in ip6_send_skb()(CVE-2024-44987)

RDMA/iwcm: Fix a use-after-free related to destroying CM IDs(CVE-2024-42285)

IB/core: Implement a limit on UMAD receive List(CVE-2024-42145)

bnx2x: Fix multiple UBSAN array-index-out-of-bounds(CVE-2024-42148)

tcp_metrics: validate source addr length(CVE-2024-42154)

kernel:bonding: Fix out-of-bounds read in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h1665.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
