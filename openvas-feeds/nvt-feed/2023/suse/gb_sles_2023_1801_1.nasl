# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1801.1");
  script_cve_id("CVE-2017-5753", "CVE-2021-3923", "CVE-2022-20567", "CVE-2023-0590", "CVE-2023-1076", "CVE-2023-1095", "CVE-2023-1281", "CVE-2023-1390", "CVE-2023-1513", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-28328", "CVE-2023-28464", "CVE-2023-28772");
  script_tag(name:"creation_date", value:"2023-04-11 04:17:30 +0000 (Tue, 11 Apr 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 00:57:52 +0000 (Fri, 07 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1801-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1801-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231801-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209798");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-April/028741.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:1801-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-5753: Fixed spectre V1 vulnerability on netlink (bsc#1209547).
- CVE-2017-5753: Fixed spectre vulnerability in prlimit (bsc#1209256).
- CVE-2021-3923: Fixed stack information leak vulnerability that could lead to kernel protection bypass in infiniband RDMA (bsc#1209778).
- CVE-2022-20567: Fixed use after free that could lead to a local privilege escalation in pppol2tp_create of l2tp_ppp.c (bsc#1208850).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2023-1076: Fixed incorrect UID assigned to tun/tap sockets (bsc#1208599).
- CVE-2023-1095: Fixed a NULL pointer dereference in nf_tables due to zeroed list head (bsc#1208777).
- CVE-2023-1281: Fixed use after free that could lead to privilege escalation in tcindex (bsc#1209634).
- CVE-2023-1390: Fixed remote DoS vulnerability in tipc_link_xmit() (bsc#1209289).
- CVE-2023-1513: Fixed an uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an information leak (bsc#1209532).
- CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler (bsc#1207036).
- CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in net/sched/sch_atm.c because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results) (bsc#1207125).
- CVE-2023-28328: Fixed a denial of service issue in az6027 driver in drivers/media/usb/dev-usb/az6027.c (bsc#1209291).
- CVE-2023-28464: Fixed user-after-free that could lead to privilege escalation in hci_conn_cleanup in net/bluetooth/hci_conn.c (bsc#1209052).
- CVE-2023-28772: Fixed buffer overflow in seq_buf_putmem_hex in lib/seq_buf.c (bsc#1209549).

The following non-security bugs were fixed:

- ARM: 8702/1: head-common.S: Clear lr before jumping to start_kernel() (git-fixes)
- Bluetooth: btusb: Add VID:PID 13d3:3529 for Realtek RTL8821CE (git-fixes).
- Bluetooth: btusb: do not call kfree_skb() under spin_lock_irqsave() (git-fixes).
- Input: atmel_mxt_ts - fix double free in mxt_read_info_block (git-fixes).
- KVM: arm64: Hide system instruction access to Trace registers (git-fixes)
- NFSv4: Fix hangs when recovering open state after a server reboot (git-fixes).
- PCI/MSI: Enforce MSI entry updates to be visible (git-fixes).
- PCI/MSI: Enforce that MSI-X table entry is masked for update (git-fixes).
- PCI/MSI: Mask all unused MSI-X entries (git-fixes).
- PCI/MSI: Skip masking MSI-X on Xen PV (git-fixes).
- PCI/PM: Always return devices to D0 when thawing (git-fixes).
- PCI/PM: Avoid using device_may_wakeup() for runtime PM (git-fixes).
- PCI: Add ACS quirk for Intel Root Complex Integrated Endpoints (git-fixes).
- PCI: Add ACS quirk for iProc PAXB (git-fixes).
- PCI: Avoid FLR for AMD Matisse HD Audio & USB 3.0 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.130.1", rls:"SLES12.0SP5"))) {
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
