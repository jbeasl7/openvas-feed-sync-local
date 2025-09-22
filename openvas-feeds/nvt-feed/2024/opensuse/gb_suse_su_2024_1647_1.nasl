# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856152");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-47047", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47187", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47191", "CVE-2021-47192", "CVE-2021-47193", "CVE-2021-47194", "CVE-2021-47195", "CVE-2021-47196", "CVE-2021-47197", "CVE-2021-47198", "CVE-2021-47199", "CVE-2021-47200", "CVE-2021-47201", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47209", "CVE-2021-47210", "CVE-2021-47211", "CVE-2021-47212", "CVE-2021-47215", "CVE-2021-47216", "CVE-2021-47217", "CVE-2021-47218", "CVE-2021-47219", "CVE-2022-48631", "CVE-2022-48637", "CVE-2022-48638", "CVE-2022-48647", "CVE-2022-48648", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48653", "CVE-2022-48654", "CVE-2022-48655", "CVE-2022-48656", "CVE-2022-48657", "CVE-2022-48660", "CVE-2022-48662", "CVE-2022-48663", "CVE-2022-48667", "CVE-2022-48668", "CVE-2023-0160", "CVE-2023-52476", "CVE-2023-52500", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52607", "CVE-2023-52616", "CVE-2023-52628", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-23850", "CVE-2024-26601", "CVE-2024-26610", "CVE-2024-26614", "CVE-2024-26642", "CVE-2024-26687", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26704", "CVE-2024-26727", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26773", "CVE-2024-26792", "CVE-2024-26816", "CVE-2024-26898", "CVE-2024-26903", "CVE-2024-27043", "CVE-2024-27389");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 19:31:26 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:35 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1647-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EO5PKRIBGFSDTOXNMKLE3BYVZ4QUQEH6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2024-27389: Fixed pstore inode handling with d_invalidate()
      (bsc#1223705).

  * CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places
      (bsc#1223824).

  * CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86
      and ARM md, raid, raid5 modules (bsc#1219169).

  * CVE-2024-23848: Fixed media/cec for possible use-after-free in
      cec_queue_msg_fh (bsc#1219104).

  * CVE-2022-48662: Fixed a general protection fault (GPF) in
      i915_perf_open_ioctl (bsc#1223505).

  * CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset
      skb->mac_header (bsc#1223513).

  * CVE-2023-52616: Fixed unexpected pointer access in crypto/lib/mpi in
      mpi_ec_init (bsc#1221612).

  * CVE-2024-26816: Fixed relocations in .notes section when building with
      CONFIG_XEN_PV=y by ignoring them (bsc#1222624).

  * CVE-2021-47207: Fixed a null pointer dereference on pointer block in gus
      (bsc#1222790).

  * CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221299).

  * CVE-2024-26687: Fixed xen/events close evtchn after mapping cleanup
      (bsc#1222435).

  * CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay
      (bsc#1220342).

  * CVE-2024-26764: Fixed IOCB_AIO_RW check in fs/aio before the struct
      aio_kiocb conversion (bsc#1222721).

  * CVE-2024-26773: Fixed ext4 block allocation from corrupted group in
      ext4_mb_try_best_found() (bsc#1222618).

  * CVE-2024-26766: Fixed SDMA off-by-one error in _pad_sdma_tx_descs()
      (bsc#1222726).

  * CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).

  * CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len
      in ext4 (bsc#1222422).

  * CVE-2023-52500: Fixed information leaking when processing
      OPC_INB_SET_CONTROLLER_CONFIG command (bsc#1220883).

  * CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to
      potentially crash the system (bsc#1209657).

  * CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter
      nf_tables (bsc#1221830).

  * CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in
      net/netfilter/nf_conntrack_netlink.c (bsc#1218479).

  * CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks
      (bsc#1221293).

  * CVE-2023-52607: Fixed NULL pointer dereference in pgtable_cache_a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.79.1", rls:"openSUSELeapMicro5.4"))) {
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