# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0618.1");
  script_cve_id("CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3564", "CVE-2022-36280", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0394", "CVE-2023-0590", "CVE-2023-23454");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 15:54:54 +0000 (Fri, 05 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0618-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230618-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208570");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/013976.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-23454: Fixed denial or service in cbq_classify in net/sched/sch_cbq.c (bnc#1207036).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2023-0394: Fixed a null pointer dereference flaw in the network subcomponent in the Linux kernel which could lead to system crash (bsc#1207168).
- CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM package. SNDRV_CTL_IOCTL_ELEM_{READ<pipe>WRITE}32 was missing locks that could have been used in a use-after-free that could have resulted in a priviledge escalation to gain ring0 access from the system user (bsc#1207134).
- CVE-2023-0045: Fixed flush IBP in ib_prctl_set() (bsc#1207773).
- CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic control subsystem (bnc#1207237).
- CVE-2022-4662: Fixed incorrect access control in the USB core subsystem that could lead a local user to crash the system (bnc#1206664).
- CVE-2022-36280: Fixed an out-of-bounds memory access vulnerability that was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_kms.c (bnc#1203332).
- CVE-2022-3564: Fixed use-after-free in l2cap_core.c of the Bluetooth component (bnc#1206073).
- CVE-2022-3108: Fixed missing check of return value of kmemdup() (bnc#1206389).
- CVE-2022-3107: Fixed missing check of return value of kvmalloc_array() (bnc#1206395).


The following non-security bugs were fixed:

- Bluetooth: hci_qca: Fix the teardown problem for real (git-fixes).
- CDC-NCM: remove 'connected' log message (git-fixes).
- HID: betop: check shape of output reports (git-fixes, bsc#1207186).
- HID: betop: fix slab-out-of-bounds Write in betop_probe (git-fixes, bsc#1207186).
- HID: check empty report_list in hid_validate_values() (git-fixes, bsc#1206784).
- Input: convert autorepeat timer to use timer_setup() (git-fixes).
- Input: do not use WARN() in input_alloc_absinfo() (git-fixes).
- Input: i8042 - Add quirk for Fujitsu Lifebook T725 (git-fixes).
- Input: iforce - reformat the packet dump output (git-fixes).
- Input: iforce - wake up after clearing IFORCE_XMIT_RUNNING flag (git-fixes).
- Input: replace hard coded string with __func__ in pr_err() (git-fixes).
- Input: switch to using sizeof(*type) when allocating memory (git-fixes).
- Input: use seq_putc() in input_seq_print_bitmap() (git-fixes).
- Input: use seq_puts() in input_devices_seq_show() (git-fixes).
- Makefile: link with -z noexecstack --no-warn-rwx-segments (bsc#1203200).
- NFS Handle missing attributes in OPEN reply (bsc#1203740).
- NFS: Correct size calculation for create reply length (git-fixes).
- NFS: Fix an Oops in nfs_d_automount() (git-fixes).
- NFS: Fix initialisation of I/O result struct in nfs_pgio_rpcsetup (git-fixes).
- NFS: Fix memory leaks in nfs_pageio_stop_mirroring() (git-fixes).
- NFS: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
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
