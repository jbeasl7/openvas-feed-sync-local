# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0478.1");
  script_cve_id("CVE-2021-33631", "CVE-2023-46838", "CVE-2023-47233", "CVE-2023-4921", "CVE-2023-51043", "CVE-2023-51780", "CVE-2023-51782", "CVE-2023-6040", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-6915", "CVE-2024-0565", "CVE-2024-0775", "CVE-2024-1086");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0478-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240478-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219434");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017919.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 LTSS kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-1086: Fixed a use-after-free vulnerability inside the nf_tables component that could have been exploited to achieve local privilege escalation (bsc#1219434).
- CVE-2024-0775: Fixed use-after-free in __ext4_remount in fs/ext4/super.c that could allow a local user to cause an information leak problem while freeing the old quota file names before a potential failure (bsc#1219053).
- CVE-2024-0565: Fixed an out-of-bounds memory read flaw in receive_encrypted_standard in fs/smb/client/smb2ops.c (bsc#1218832).
- CVE-2023-6915: Fixed a NULL pointer dereference problem in ida_free in lib/idr.c (bsc#1218804).
- CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
- CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
- CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
- CVE-2023-6040: Fixed an out-of-bounds access vulnerability while creating a new netfilter table, lack of a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function (bsc#1218752).
- CVE-2023-51782: Fixed use-after-free in rose_ioctl in net/rose/af_rose.c because of a rose_accept race condition (bsc#1218757).
- CVE-2023-51780: Fixed a use-after-free in do_vcc_ioctl in net/atm/ioctl.c, because of a vcc_recvmsg race condition (bsc#1218730).
- CVE-2023-51043: Fixed use-after-free during a race condition between a nonblocking atomic commit and a driver unload in drivers/gpu/drm/drm_atomic.c (bsc#1219120).
- CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network scheduler which could be exploited to achieve local privilege escalation (bsc#1215275).
- CVE-2023-47233: Fixed a use-after-free in the device unplugging (disconnect the USB by hotplug) code inside the brcm80211 component (bsc#1216702).
- CVE-2023-46838: Fixed an issue with Xen netback processing of zero-length transmit fragment (bsc#1218836).
- CVE-2021-33631: Fixed an integer overflow in ext4_write_inline_data_end() (bsc#1219412).

The following non-security bugs were fixed:

- build: Limit kernel-source build to architectures for which the kernel binary is built (bsc#1108281).
- docs: Store the old kernel changelog entries in kernel-docs package (bsc#1218713)
- mkspec: Include constraints for both multibuild and plain package always
- rpm/kernel-docs.spec.in: fix build with 6.8 Since upstream commit f061c9f7d058
- rpm/kernel-source.rpmlintrc: add action-ebpf Upstream commit a79d8ba734bd
- rpm/mkspec: use kernel-source: prefix for constraints on multibuild Otherwise the constraints are not applied with multibuild enabled.
- x86/entry/ia32: Ensure s32 is sign extended to s64 (bsc#1193285).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.178.1.150200.9.91.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.178.1", rls:"SLES15.0SP2"))) {
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
