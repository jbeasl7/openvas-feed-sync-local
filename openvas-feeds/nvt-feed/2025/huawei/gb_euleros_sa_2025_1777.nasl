# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1777");
  script_cve_id("CVE-2021-47634", "CVE-2021-47659", "CVE-2022-48758", "CVE-2022-49044", "CVE-2022-49086", "CVE-2022-49100", "CVE-2022-49155", "CVE-2022-49280", "CVE-2022-49307", "CVE-2022-49350", "CVE-2022-49370", "CVE-2022-49385", "CVE-2022-49388", "CVE-2022-49390", "CVE-2022-49441", "CVE-2022-49450", "CVE-2022-49513", "CVE-2022-49535", "CVE-2022-49603", "CVE-2022-49648", "CVE-2022-49674", "CVE-2022-49753", "CVE-2023-52730", "CVE-2023-52935", "CVE-2023-52973", "CVE-2023-52997", "CVE-2023-53005", "CVE-2023-53007", "CVE-2023-53019", "CVE-2023-53024", "CVE-2023-53032", "CVE-2024-35893", "CVE-2024-35947", "CVE-2024-45008", "CVE-2024-53168", "CVE-2024-57931", "CVE-2024-57977", "CVE-2024-57980", "CVE-2024-57996", "CVE-2025-21700", "CVE-2025-21702", "CVE-2025-21785", "CVE-2025-21791", "CVE-2025-21796", "CVE-2025-21806", "CVE-2025-21858", "CVE-2025-37752", "CVE-2025-37785");
  script_tag(name:"creation_date", value:"2025-07-11 04:39:00 +0000 (Fri, 11 Jul 2025)");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-12 14:15:15 +0000 (Wed, 12 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1777)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1777");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1777");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1777 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"drm/plane: Move range check for format_count earlier(CVE-2021-47659)

trace_events_hist: add check for return value of 'create_hist_field'(CVE-2023-53005)

tracing: Make sure trace_printk() can output as soon as it can be used(CVE-2023-53007)

bpf: Fix pointer-leak due to insufficient speculative store bypass mitigation(CVE-2023-53024)

sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket(CVE-2024-53168)

tracing/histograms: Fix memory leak problem(CVE-2022-49648)

vrf: use RCU protection in l3mdev_l3_out().(CVE-2025-21791)

net_sched: sch_sfq: don't allow 1 packet limit(CVE-2024-57996)

net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21700)

geneve: Fix use-after-free in geneve_find_dev().(CVE-2025-21858)

macsec: fix UAF bug for real_dev(CVE-2022-49390)

net: let net.core.dev_weight always be non-zero(CVE-2025-21806)

net: mdio: unexport __init-annotated mdio_bus_init().(CVE-2022-49350)

ip: Fix data-races around sysctl_ip_fwd_update_priority.(CVE-2022-49603)

mmc: sdio: fix possible resource leaks in some error paths(CVE-2023-52730)

ipv4: prevent potential spectre v1 gadget in ip_metrics_convert().(CVE-2023-52997)

net: sched: Disallow replacing of child qdisc from one parent to another(CVE-2025-21702)

net/sched: act_skbmod: prevent kernel-infoleak(CVE-2024-35893)

netfilter: ipset: Fix overflow before widen in the bitmap_ip_create() function.(CVE-2023-53032)

net: openvswitch: fix leak of nested actions(CVE-2022-49086)

net: mdio: validate parameter addr in mdiobus_get_phy().(CVE-2023-53019)

selinux: ignore unknown extended permissions(CVE-2024-57931)

vc_screen: move load of struct vc_data pointer in vcs_read() to avoid UAF(CVE-2023-52973)

driver: base: fix UAF when driver_attach failed(CVE-2022-49385)

scsi: bnx2fc: Flush destroy_work queue before calling bnx2fc_interface_put().(CVE-2022-48758)

rxrpc: Fix listen() setting the bar too high for the prealloc rings(CVE-2022-49450)

ubi: Fix race condition between ctrl_cdev_ioctl and ubi_cdev_ioctl(CVE-2021-47634)

media: uvcvideo: Fix double free in error path(CVE-2024-57980)

scsi: lpfc: Fix null pointer dereference after failing to issue FLOGI and PLOGI(CVE-2022-49535)

dmaengine: Fix double increment of client_count in dma_chan_get().(CVE-2022-49753)

memcg: fix soft lockup in the OOM process(CVE-2024-57977)

firmware: dmi-sysfs: Fix memory leak in dmi_sysfs_register_handle(CVE-2022-49370)

dm raid: fix accesses beyond end of raid member array(CVE-2022-49674)

nfsd: clear acl_access/acl_default after releasing them(CVE-2025-21796)

Input: MT - limit max slots(CVE-2024-45008)(CVE-2024-45008)

ubi: ubi_create_volume: Fix use-after-free when volume creation failed(CVE-2022-49388)

scsi: qla2xxx: Suppress a kernel complaint in qla_create_qpair().(CVE-2022-49155)

NFSD: prevent underflow in nfssvc_decode_writeargs().(CVE-2022-49280)

dm integrity: fix memory corruption when ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.90~vhulk2211.3.0.h2036.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
