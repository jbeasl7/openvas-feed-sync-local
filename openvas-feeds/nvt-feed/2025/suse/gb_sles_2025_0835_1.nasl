# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0835.1");
  script_cve_id("CVE-2022-49080", "CVE-2023-1192", "CVE-2023-52572", "CVE-2024-35949", "CVE-2024-50115", "CVE-2024-50128", "CVE-2024-53135", "CVE-2024-53173", "CVE-2024-53239", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56605", "CVE-2024-57948", "CVE-2025-21690", "CVE-2025-21692", "CVE-2025-21699");
  script_tag(name:"creation_date", value:"2025-03-13 04:07:10 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-21 15:59:44 +0000 (Fri, 21 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0835-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250835-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238033");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020498.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49080: mm/mempolicy: fix mpol_new leak in shared_policy_replace (bsc#1238033).
- CVE-2024-35949: btrfs: make sure that WRITTEN is set on all metadata blocks (bsc#1224700).
- CVE-2024-50128: net: wwan: fix global oob in wwan_rtnl_policy (bsc#1232905).
- CVE-2024-53135: KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN (bsc#1234154).
- CVE-2024-57948: mac802154: check local interfaces before deleting sdata list (bsc#1236677).
- CVE-2025-21690: scsi: storvsc: Ratelimit warning logs to prevent VM denial of service (bsc#1237025).
- CVE-2025-21692: net: sched: fix ets qdisc OOB Indexing (bsc#1237028).
- CVE-2025-21699: gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag (bsc#1237139).

The following non-security bugs were fixed:

- idpf: call set_real_num_queues in idpf_open (bsc#1236661 bsc#1237316).
- ipv4/tcp: do not use per netns ctl sockets (bsc#1237693).
- net: mana: Add get_link and get_link_ksettings in ethtool (bsc#1236761).
- net: mana: Cleanup 'mana' debugfs dir after cleanup of all children (bsc#1236760).
- net: mana: Enable debugfs files for MANA device (bsc#1236758).
- net: netvsc: Update default VMBus channels (bsc#1236757).
- scsi: storvsc: Use scsi_cmd_to_rq() instead of scsi_cmnd.request (git-fixes).
- x86/kvm: fix is_stale_page_fault() (bsc#1236675).
- x86/xen: add FRAME_END to xen_hypercall_hvm() (git-fixes).
- x86/xen: fix xen_hypercall_hvm() to not clobber %rbx (git-fixes).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.153.1.150400.24.76.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.153.1", rls:"SLES15.0SP4"))) {
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
