# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03204.1");
  script_cve_id("CVE-2022-49967", "CVE-2022-49975", "CVE-2022-49980", "CVE-2022-49981", "CVE-2022-50007", "CVE-2022-50066", "CVE-2022-50080", "CVE-2022-50116", "CVE-2022-50127", "CVE-2022-50138", "CVE-2022-50141", "CVE-2022-50162", "CVE-2022-50185", "CVE-2022-50191", "CVE-2022-50228", "CVE-2022-50229", "CVE-2023-52813", "CVE-2023-53020", "CVE-2024-28956", "CVE-2025-22022", "CVE-2025-23141", "CVE-2025-38075", "CVE-2025-38102", "CVE-2025-38103", "CVE-2025-38117", "CVE-2025-38122", "CVE-2025-38153", "CVE-2025-38173", "CVE-2025-38174", "CVE-2025-38184", "CVE-2025-38185", "CVE-2025-38190", "CVE-2025-38214", "CVE-2025-38245", "CVE-2025-38263", "CVE-2025-38313", "CVE-2025-38352", "CVE-2025-38386", "CVE-2025-38424", "CVE-2025-38430", "CVE-2025-38449", "CVE-2025-38457", "CVE-2025-38460", "CVE-2025-38464", "CVE-2025-38465", "CVE-2025-38470", "CVE-2025-38473", "CVE-2025-38474", "CVE-2025-38498", "CVE-2025-38499", "CVE-2025-38512", "CVE-2025-38513", "CVE-2025-38515", "CVE-2025-38546", "CVE-2025-38556", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38644");
  script_tag(name:"creation_date", value:"2025-09-15 04:11:52 +0000 (Mon, 15 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 19:41:50 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03204-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503204-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248748");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041681.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:03204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49967: bpf: Fix a data-race around bpf_jit_limit (bsc#1244964).
- CVE-2022-49975: bpf: Don't redirect packets with invalid pkt_len (bsc#1245196).
- CVE-2022-49980: usb: gadget: Fix use-after-free bug by not setting udc->dev.driver (bsc#1245110).
- CVE-2022-49981: HID: hidraw: fix memory leak in hidraw_release() (bsc#1245072).
- CVE-2022-50007: xfrm: fix refcount leak in __xfrm_policy_check() (bsc#1245016).
- CVE-2022-50066: net: atlantic: fix aq_vec index out of range error (bsc#1244985).
- CVE-2022-50080: tee: add overflow check in register_shm_helper() (bsc#1244972).
- CVE-2022-50116: kernel: tty: n_gsm: fix deadlock and link starvation in outgoing data path (bsc#1244824).
- CVE-2022-50127: RDMA/rxe: Fix error unwind in rxe_create_qp() (bsc#1244815).
- CVE-2022-50138: RDMA/qedr: Fix potential memory leak in __qedr_alloc_mr() (bsc#1244797).
- CVE-2022-50141: mmc: sdhci-of-esdhc: Fix refcount leak in esdhc_signal_voltage_switch (bsc#1244794).
- CVE-2022-50162: wifi: libertas: Fix possible refcount leak in if_usb_probe() (bsc#1244773).
- CVE-2022-50185: drm/radeon: fix potential buffer overflow in ni_set_mc_special_registers() (bsc#1244887).
- CVE-2022-50191: regulator: of: Fix refcount leak bug in of_get_regulation_constraints() (bsc#1244899).
- CVE-2022-50228: KVM: SVM: Do not BUG if userspace injects an interrupt with GIF=0 (bsc#1244854).
- CVE-2022-50229: ALSA: bcd2000: Fix a UAF bug on the error path of probing (bsc#1244856).
- CVE-2023-52813: crypto: pcrypt - Fix hungtask for PADATA_RESET (bsc#1225527).
- CVE-2023-53020: l2tp: close all race conditions in l2tp_tunnel_register() (bsc#1240224).
- CVE-2024-28956: x86/its: Enable Indirect Target Selection mitigation (bsc#1242006).
- CVE-2025-22022: usb: xhci: Apply the link chain quirk on NEC isoc endpoints (bsc#1241292).
- CVE-2025-23141: KVM: x86: Acquire SRCU in KVM_GET_MP_STATE to protect guest memory accesses (bsc#1242782).
- CVE-2025-38075: scsi: target: iscsi: Fix timeout on deleted connection (bsc#1244734).
- CVE-2025-38102: VMCI: fix race between vmci_host_setup_notify and vmci_ctx_unset_notify (bsc#1245669).
- CVE-2025-38103: HID: usbhid: Eliminate recurrent out-of-bounds bug in usbhid_parse() (bsc#1245663).
- CVE-2025-38117: Bluetooth: MGMT: protect mgmt_pending list with its own lock (bsc#1245695).
- CVE-2025-38122: gve: add missing NULL check for gve_alloc_pending_packet() in TX DQO (bsc#1245746).
- CVE-2025-38153: net: usb: aqc111: fix error handling of usbnet read calls (bsc#1245744).
- CVE-2025-38173: crypto: marvell/cesa - Handle zero-length skcipher requests (bsc#1245769).
- CVE-2025-38174: thunderbolt: Do not double dequeue a configuration request (bsc#1245781).
- CVE-2025-38184: tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.272.1", rls:"SLES12.0SP5"))) {
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
