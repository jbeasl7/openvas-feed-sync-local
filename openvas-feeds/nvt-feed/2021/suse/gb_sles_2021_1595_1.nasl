# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1595.1");
  script_cve_id("CVE-2020-36310", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-28950", "CVE-2021-29155", "CVE-2021-29650", "CVE-2021-3444");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-05 20:08:10 +0000 (Mon, 05 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1595-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211595-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185549");
  script_xref(name:"URL", value:"https://github.com/openSUSE/openSUSE-release-tools/issues/2439");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-May/008769.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-36312: Fixed an issue within virt/kvm/kvm_main.c that had a kvm_io_bus_unregister_dev memory leak upon a kmalloc failure (bnc#1184509).
- CVE-2021-29650: Fixed an issue within the netfilter subsystem that allowed attackers to cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a full memory barrier upon the assignment of a new table value (bnc#1184208).
- CVE-2021-29155: Fixed an issue within kernel/bpf/verifier.c that performed undesirable out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer arithmetic operations, the pointer modification performed by the first operation is not correctly accounted for when restricting subsequent operations (bnc#1184942).
- CVE-2020-36310: Fixed an issue within arch/x86/kvm/svm/svm.c that allowed a set_memory_region_test infinite loop for certain nested page faults (bnc#1184512).
- CVE-2021-28950: Fixed an issue within fs/fuse/fuse_i.h where a 'stall on CPU' could have occurred because a retry loop continually finds the same bad inode (bnc#1184194, bnc#1184211).
- CVE-2020-36322: Fixed an issue within the FUSE filesystem implementation where fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as CVE-2021-28950 (bnc#1184211, bnc#1184952).
- CVE-2021-3444: Fixed incorrect mod32 BPF verifier truncation (bsc#1184170).

The following non-security bugs were fixed:

- arm64: PCI: mobiveil: remove driver Prepare to replace it with upstreamed driver
- blk-settings: align max_sectors on 'logical_block_size' boundary (bsc#1185195).
- block: fix use-after-free on cached last_lookup partition (bsc#1181062).
- block: recalculate segment count for multi-segment discards correctly (bsc#1184724).
- btrfs: fix qgroup data rsv leak caused by falloc failure (bsc#1185549).
- btrfs: track qgroup released data in own variable in insert_prealloc_file_extent (bsc#1185549).
- cdc-acm: fix BREAK rx code path adding necessary calls (git-fixes).
- cxgb4: avoid collecting SGE_QBASE regs during traffic (bsc#1097585 bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).
- drivers/perf: thunderx2_pmu: Fix memory resource error handling (git-fixes).
- ext4: find old entry again if failed to rename whiteout (bsc#1184742).
- ext4: fix potential error in ext4_do_update_inode (bsc#1184731).
- fs: direct-io: fix missing sdio->boundary (bsc#1184736).
- handle also the opposite type of race condition
- i40e: Fix display statistics for veb_tc (bsc#1111981).
- i40e: Fix kernel oops when ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.71.1", rls:"SLES12.0SP5"))) {
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
