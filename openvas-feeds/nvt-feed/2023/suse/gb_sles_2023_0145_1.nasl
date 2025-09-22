# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0145.1");
  script_cve_id("CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3564", "CVE-2022-4662", "CVE-2023-0394", "CVE-2023-23454");
  script_tag(name:"creation_date", value:"2023-01-27 04:21:47 +0000 (Fri, 27 Jan 2023)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-13 18:31:32 +0000 (Tue, 13 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0145-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230145-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207195");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-January/013526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2022-4662: Fixed a recursive locking violation in usb-storage that can cause the kernel to deadlock. (bsc#1206664)
- CVE-2022-3564: Fixed a bug which could lead to use after free, it was found in the function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. (bsc#1206073)
- CVE-2022-3108: Fixed a bug in kfd_parse_subtype_iolink in drivers/gpu/drm/amd/amdkfd/kfd_crat.c where a lack of check of the return value of kmemdup() could lead to a NULL pointer dereference. (bsc#1206389)
- CVE-2023-23454: Fixed a type confusion bug in the CBQ network scheduler which could lead to a use-after-free (bsc#1207036)
- CVE-2022-3107: Fixed a null pointer dereference caused by a missing check of the return value of kvmalloc_array. (bsc#1206395)
- CVE-2023-0394: Fixed a null pointer dereference flaw in the network subcomponent in the Linux kernel which could lead to system crash (bsc#1207168).

The following non-security bugs were fixed:

- arm64: alternative: Use true and false for boolean values (git-fixes)
- arm64: cmpwait: Clear event register before arming exclusive monitor (git-fixes)
- arm64: Fix minor issues with the dcache_by_line_op macro (git-fixes)
- arm64: fix possible spectre-v1 in ptrace_hbp_get_event() (git-fixes)
- arm64: fix possible spectre-v1 write in ptrace_hbp_set_event() (git-fixes)
- arm64: ftrace: do not adjust the LR value (git-fixes)
- arm64: io: Ensure calls to delay routines are ordered against prior (git-fixes)
- arm64: io: Ensure value passed to __iormb() is held in a 64-bit (git-fixes)
- arm64: jump_label.h: use asm_volatile_goto macro instead of 'asm (git-fixes)
- arm64: make secondary_start_kernel() notrace (git-fixes)
- arm64: makefile fix build of .i file in external module case (git-fixes)
- arm64: ptrace: remove addr_limit manipulation (git-fixes)
- arm64: rockchip: Force CONFIG_PM on Rockchip systems (git-fixes)
- arm64: smp: Handle errors reported by the firmware (git-fixes)
- arm64/kvm: consistently handle host HCR_EL2 flags (git-fixes)
- Bluetooth: hci_qca: Fix the teardown problem for real (git-fixes).
- CDC-NCM: remove 'connected' log message (git-fixes).
- ceph: remove bogus checks and WARN_ONs from ceph_set_page_dirty (bsc#1207195).
- flexfiles: enforce per-mirror stateid only for v4 DSes (git-fixes).
- flexfiles: use per-mirror specified stateid for IO (git-fixes).
- fs: nfs: Fix possible null-pointer dereferences in encode_attrs() (git-fixes).
- ibmveth: Always stop tx queues during close (bsc#1065729).
- ipv6: raw: Deduct extension header length in rawv6_push_pending_frames (bsc#1207168).
- kABI: mitigate new ufs_stats field (git-fixes).
- lockd: fix decoding of TEST results (git-fixes).
- media: Do not let tvp5150_get_vbi() go out of vbi_ram_default array ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.147.1", rls:"SLES12.0SP5"))) {
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
