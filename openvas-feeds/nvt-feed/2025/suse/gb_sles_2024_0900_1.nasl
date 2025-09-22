# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0900.1");
  script_cve_id("CVE-2019-25162", "CVE-2021-46923", "CVE-2021-46924", "CVE-2021-46932", "CVE-2021-46934", "CVE-2021-47083", "CVE-2022-48627", "CVE-2023-28746", "CVE-2023-5197", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52452", "CVE-2023-52456", "CVE-2023-52457", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52467", "CVE-2023-52475", "CVE-2023-52478", "CVE-2023-52482", "CVE-2023-52484", "CVE-2023-52530", "CVE-2023-52531", "CVE-2023-52559", "CVE-2023-6270", "CVE-2023-6817", "CVE-2024-0607", "CVE-2024-1151", "CVE-2024-23849", "CVE-2024-23850", "CVE-2024-23851", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26591", "CVE-2024-26593", "CVE-2024-26595", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26607", "CVE-2024-26622");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 17:36:15 +0000 (Wed, 11 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0900-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0900-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240900-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220933");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018167.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0900-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
- CVE-2023-52463: Fixed null pointer dereference in efivarfs (bsc#1220328).
- CVE-2023-52559: Fixed a bug by avoiding memory allocation in iommu_suspend (bsc#1220933).
- CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
- CVE-2023-52530: Fixed a potential key use-after-free in wifi mac80211 (bsc#1220930).
- CVE-2024-26607: Fixed a probing race issue in sii902x: (bsc#1220736).
- CVE-2023-52467: Fixed a null pointer dereference in of_syscon_register (bsc#1220433).
- CVE-2024-26591: Fixed re-attachment branch in bpf_tracing_prog_attach (bsc#1220254).
- CVE-2024-26589: Fixed out of bounds read due to variable offset alu on PTR_TO_FLOW_KEYS (bsc#1220255).
- CVE-2023-52484: Fixed a soft lockup triggered by arm_smmu_mm_invalidate_range (bsc#1220797).
- CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
- CVE-2023-52340: Fixed ICMPv6 'Packet Too Big' packets force a DoS of the Linux kernel by forcing 100% CPU (bsc#1219295).
- CVE-2024-0607: Fixed 64-bit load issue in nft_byteorder_eval() (bsc#1218915).
- CVE-2023-6817: Fixed use-after-free in nft_pipapo_walk (bsc#1218195).
- CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control() (bsc#1220825).
- CVE-2024-23850: Fixed double free of anonymous device after snapshot creation failure (bsc#1219126).
- CVE-2023-52452: Fixed Fix accesses to uninit stack slots (bsc#1220257).
- CVE-2023-52457: Fixed skipped resource freeing if pm_runtime_resume_and_get() failed (bsc#1220350).
- CVE-2023-52456: Fixed tx statemachine deadlock (bsc#1220364).
- CVE-2023-52451: Fixed access beyond end of drmem array (bsc#1220250).
- CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier (bsc#1220238).
- CVE-2021-46923: Fixed reference leakage in fs/mount_setattr (bsc#1220457).
- CVE-2023-52447: Fixed map_fd_put_ptr() signature kABI workaround (bsc#1220251).
- CVE-2024-26598: Fixed potential UAF in LPI translation cache (bsc#1220326).
- CVE-2024-26603: Fixed infinite loop via #PF handling (bsc#1220335).
- CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).
- CVE-2023-52439: Fixed use-after-free in uio_open (bsc#1220140).
- CVE-2023-52443: Fixed crash when parsed profile name is empty (bsc#1220240).
- CVE-2024-26602: Fixed overall slowdowns with sys_membarrier (bsc1220398).
- CVE-2024-26593: Fixed block process call transactions (bsc#1220009).
- CVE-2024-26586: Fixed stack corruption (bsc#1220243).
- CVE-2024-26595: Fixed NULL pointer dereference in error path (bsc#1220344).
- CVE-2023-52464: Fixed possible out-of-bounds string access (bsc#1220330)
- CVE-2023-52448: Fixed kernel NULL pointer dereference in gfs2_rgrp_dump (bsc#1220253).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.111.2.150400.24.52.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.111.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.111.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.111.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.111.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.111.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.111.2", rls:"SLES15.0SP4"))) {
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
