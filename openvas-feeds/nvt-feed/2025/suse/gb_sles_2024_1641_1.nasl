# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1641.1");
  script_cve_id("CVE-2021-47047", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47187", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47191", "CVE-2021-47192", "CVE-2021-47193", "CVE-2021-47194", "CVE-2021-47195", "CVE-2021-47196", "CVE-2021-47197", "CVE-2021-47198", "CVE-2021-47199", "CVE-2021-47200", "CVE-2021-47201", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47209", "CVE-2021-47210", "CVE-2021-47211", "CVE-2021-47212", "CVE-2021-47215", "CVE-2021-47216", "CVE-2021-47217", "CVE-2021-47218", "CVE-2021-47219", "CVE-2022-48631", "CVE-2022-48637", "CVE-2022-48638", "CVE-2022-48647", "CVE-2022-48648", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48653", "CVE-2022-48654", "CVE-2022-48655", "CVE-2022-48656", "CVE-2022-48657", "CVE-2022-48660", "CVE-2022-48662", "CVE-2022-48663", "CVE-2022-48667", "CVE-2022-48668", "CVE-2023-0160", "CVE-2023-4881", "CVE-2023-52476", "CVE-2023-52500", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52607", "CVE-2023-52616", "CVE-2023-52628", "CVE-2023-6270", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-23850", "CVE-2024-25742", "CVE-2024-26601", "CVE-2024-26610", "CVE-2024-26614", "CVE-2024-26642", "CVE-2024-26687", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26704", "CVE-2024-26727", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26773", "CVE-2024-26792", "CVE-2024-26816", "CVE-2024-26898", "CVE-2024-26903", "CVE-2024-27043", "CVE-2024-27389");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-23 19:13:31 +0000 (Mon, 23 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1641-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1641-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241641-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035266.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1641-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 LTSS kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-27389: Fixed pstore inode handling with d_invalidate() (bsc#1223705).
- CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
- CVE-2024-26816: Ignore relocations in .notes section when building with CONFIG_XEN_PV=y (bsc#1222624).
- CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found() (bsc#1222618).
- CVE-2024-26766: Fixed SDMA off-by-one error in _pad_sdma_tx_descs() (bsc#1222726).
- CVE-2024-26764: Fixed IOCB_AIO_RW check in fs/aio before the struct aio_kiocb conversion (bsc#1222721).
- CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
- CVE-2024-26727: Fixed assertion if a newly created btrfs subvolume already gets read (bsc#1222536).
- CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
- CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).
- CVE-2024-26687: Fixed xen/events close evtchn after mapping cleanup (bsc#1222435).
- CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
- CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
- CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221299).
- CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
- CVE-2024-25742: Fixed insufficient validation during #VC instruction emulation in x86/sev (bsc#1221725).
- CVE-2024-23850: Fixed double free of anonymous device after snapshot creation failure (bsc#1219126).
- CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5 modules (bsc#1219169).
- CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
- CVE-2024-0841: Fixed a null pointer dereference in the hugetlbfs_fill_super function in hugetlbfs (HugeTLB pages) functionality (bsc#1219264).
- CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in net/netfilter/nf_conntrack_netlink.c (bsc#1218479).
- CVE-2023-7042: Fixed a null-pointer-dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() (bsc#1218336).
- CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
- CVE-2023-52628: Fixed 4-byte stack OOB write in nftables (bsc#1222117).
- CVE-2023-52616: Fixed unexpected pointer access in crypto/lib/mpi in mpi_ec_init (bsc#1221612).
- CVE-2023-52607: Fixed NULL pointer dereference in pgtable_cache_add kasprintf() (bsc#1221061).
- CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
- CVE-2023-52590: Fixed a possible ocfs2 filesystem corruption via directory renaming (bsc#1221088).
- CVE-2023-52500: Fixed information leaking when ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.119.1.150400.24.56.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.119.1", rls:"SLES15.0SP4"))) {
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
