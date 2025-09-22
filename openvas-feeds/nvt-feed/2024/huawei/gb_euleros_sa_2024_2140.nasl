# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2140");
  script_cve_id("CVE-2021-46984", "CVE-2021-47077", "CVE-2021-47101", "CVE-2021-47131", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47167", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47182", "CVE-2021-47185", "CVE-2021-47203", "CVE-2021-47497", "CVE-2022-48697", "CVE-2023-52478", "CVE-2023-52515", "CVE-2023-52587", "CVE-2023-52597", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2024-23307", "CVE-2024-24855", "CVE-2024-26598", "CVE-2024-26614", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26686", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26759", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26828", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26865", "CVE-2024-26872", "CVE-2024-26878", "CVE-2024-26882", "CVE-2024-26884", "CVE-2024-26894", "CVE-2024-26901", "CVE-2024-26915", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26973", "CVE-2024-26976", "CVE-2024-26982", "CVE-2024-26993", "CVE-2024-27008", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27019", "CVE-2024-27046", "CVE-2024-27059", "CVE-2024-27395", "CVE-2024-27437", "CVE-2024-35950");
  script_tag(name:"creation_date", value:"2024-08-20 04:40:56 +0000 (Tue, 20 Aug 2024)");
  script_version("2025-01-15T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 14:27:22 +0000 (Tue, 14 Jan 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2140");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2140");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: kyber: fix out of bounds access when preempted __blk_mq_sched_bio_merge() gets the ctx and hctx for the current CPU and passes the hctx to ->bio_merge(). kyber_bio_merge() then gets the ctx for the current CPU again and uses that to get the corresponding Kyber context in the passed hctx. However, the thread may be preempted between the two calls to blk_mq_get_ctx(), and the ctx returned the second time may no longer correspond to the passed hctx. This 'works' accidentally most of the time, but it can cause us to read garbage if the second ctx came from an hctx with more ctx's than the first one (i.e., if ctx->index_hw[hctx->type] > hctx->nr_ctx). (CVE-2021-46984)

In the Linux kernel, the following vulnerability has been resolved: scsi: qedf: Add pointer checks in qedf_update_link_speed() The following trace was observed: [ 14.042059] Call Trace: [ 14.042061] <IRQ> [ 14.042068] qedf_link_update+0x144/0x1f0 [qedf] [ 14.042117] qed_link_update+0x5c/0x80 [qed] [ 14.042135] qed_mcp_handle_link_change+0x2d2/0x410 [qed] [ 14.042155] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042170] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042186] ? qed_rd+0x13/0x40 [qed] [ 14.042205] qed_mcp_handle_events+0x437/0x690 [qed] [ 14.042221] ? qed_set_ptt+0x70/0x80 [qed] [ 14.042239] qed_int_sp_dpc+0x3a6/0x3e0 [qed] [ 14.042245] tasklet_action_common.isra.14+0x5a/0x100 [ 14.042250] __do_softirq+0xe4/0x2f8 [ 14.042253] irq_exit+0xf7/0x100 [ 14.042255] do_IRQ+0x7f/0xd0 [ 14.042257] common_interrupt+0xf/0xf [ 14.042259] </IRQ> API qedf_link_update() is getting called from QED but by that time shost_data is not initialised. This results in a NULL pointer dereference when we try to dereference shost_data while updating supported_speeds. Add a NULL pointer check before dereferencing shost_dat(CVE-2021-47077)

In the Linux kernel, the following vulnerability has been resolved: asix: fix uninit-value in asix_mdio_read() asix_read_cmd() may read less than sizeof(smsr) bytes and in this case smsr will be uninitialized. (CVE-2021-47101)

In the Linux kernel, the following vulnerability has been resolved: net/tls: Fix use-after-free after the TLS device goes down and up When a netdev with active TLS offload goes down, tls_device_down is called to stop the offload and tear down the TLS context. However, the socket stays alive, and it still points to the TLS context, which is now deallocated. If a netdev goes up, while the connection is still active, and the data flow resumes after a number of TCP retransmissions, it will lead to a use-after-free of the TLS context. This commit addresses this bug by keeping the context alive until its normal destruction, and implements the necessary fallbacks, so that the connection can resume in software (non-offloaded) kTLS mode. On the TX side tls_sw_fallback is used to encrypt all packets. The RX side already has all the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1804.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1804.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1804.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1804.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1804.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
