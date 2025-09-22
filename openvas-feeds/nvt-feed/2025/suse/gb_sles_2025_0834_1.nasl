# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0834.1");
  script_cve_id("CVE-2021-22543", "CVE-2021-37159", "CVE-2021-47634", "CVE-2021-47644", "CVE-2022-2991", "CVE-2022-48636", "CVE-2022-48650", "CVE-2022-48664", "CVE-2022-48953", "CVE-2022-48975", "CVE-2022-49006", "CVE-2022-49076", "CVE-2022-49080", "CVE-2022-49089", "CVE-2022-49124", "CVE-2022-49134", "CVE-2022-49135", "CVE-2022-49151", "CVE-2022-49178", "CVE-2022-49182", "CVE-2022-49201", "CVE-2022-49247", "CVE-2022-49490", "CVE-2022-49626", "CVE-2022-49661", "CVE-2023-0394", "CVE-2023-52572", "CVE-2023-52646", "CVE-2023-52653", "CVE-2023-52853", "CVE-2023-52924", "CVE-2023-6606", "CVE-2024-23307", "CVE-2024-26810", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-26931", "CVE-2024-27054", "CVE-2024-27388", "CVE-2024-27397", "CVE-2024-47701", "CVE-2024-49867", "CVE-2024-49884", "CVE-2024-49950", "CVE-2024-49963", "CVE-2024-49975", "CVE-2024-50036", "CVE-2024-50067", "CVE-2024-50073", "CVE-2024-50115", "CVE-2024-50251", "CVE-2024-50304", "CVE-2024-53173", "CVE-2024-53217", "CVE-2024-53239", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56605", "CVE-2024-56633", "CVE-2024-56647", "CVE-2024-56658", "CVE-2024-56688", "CVE-2024-57896", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21673", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21700", "CVE-2025-21753");
  script_tag(name:"creation_date", value:"2025-03-13 04:07:10 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 17:45:10 +0000 (Tue, 21 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0834-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250834-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238275");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020497.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2021-22543: Fixed improper handling of VM_IO<pipe>VM_PFNMAP vmas in KVM (bsc#1186482).
- CVE-2021-47634: ubi: Fix race condition between ctrl_cdev_ioctl and ubi_cdev_ioctl (bsc#1237758).
- CVE-2021-47644: media: staging: media: zoran: move videodev alloc (bsc#1237766).
- CVE-2022-48953: rtc: cmos: fix build on non-ACPI platforms (bsc#1231941).
- CVE-2022-48975: gpiolib: fix memory leak in gpiochip_setup_dev() (bsc#1231885).
- CVE-2022-49006: tracing: Free buffers when a used dynamic event is removed (bsc#1232163).
- CVE-2022-49076: RDMA/hfi1: Fix use-after-free bug for mm struct (bsc#1237738).
- CVE-2022-49080: mm/mempolicy: fix mpol_new leak in shared_policy_replace (bsc#1238033).
- CVE-2022-49089: IB/rdmavt: add lock to call to rvt_error_qp to prevent a race condition (bsc#1238041).
- CVE-2022-49124: x86/mce: Work around an erratum on fast string copy instructions (bsc#1238148).
- CVE-2022-49134: mlxsw: spectrum: Guard against invalid local ports (bsc#1237982).
- CVE-2022-49135: drm/amd/display: Fix memory leak (bsc#1238006).
- CVE-2022-49151: can: mcba_usb: properly check endpoint type (bsc#1237778).
- CVE-2022-49178: memstick/mspro_block: fix handling of read-only devices (bsc#1238107).
- CVE-2022-49182: net: hns3: add vlan list lock to protect vlan list (bsc#1238260).
- CVE-2022-49201: ibmvnic: fix race between xmit and reset (bsc#1238256).
- CVE-2022-49247: media: stk1160: If start stream fails, return buffers with VB2_BUF_STATE_QUEUED (bsc#1237783).
- CVE-2022-49490: drm/msm/mdp5: Return error code in mdp5_pipe_release when deadlock is (bsc#1238275).
- CVE-2022-49626: sfc: fix use after free when disabling sriov (bsc#1238270).
- CVE-2022-49661: can: gs_usb: gs_usb_open/close(): fix memory leak (bsc#1237788).
- CVE-2023-52572: Fixed UAF in cifs_demultiplex_thread() in cifs (bsc#1220946).
- CVE-2023-52853: hid: cp2112: Fix duplicate workqueue initialization (bsc#1224988).
- CVE-2023-52924: netfilter: nf_tables: do not skip expired elements during walk (bsc#1236821).
- CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
- CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5 modules (bsc#1219169).
- CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element timeout (bsc#1224095).
- CVE-2024-49963: mailbox: bcm2835: Fix timeout during suspend mode (bsc#1232147).
- CVE-2024-49975: uprobes: fix kernel info leak via '[uprobes]' vma (bsc#1232104).
- CVE-2024-50036: net: do not delay dst_entries_add() in dst_release() (bsc#1231912).
- CVE-2024-50067: uprobe: avoid out-of-bounds memory access of fetching args (bsc#1232416).
- CVE-2024-50251: netfilter: nft_payload: sanitize offset and length before calling ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.250.1", rls:"SLES12.0SP5"))) {
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
