# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833678");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-21400", "CVE-2023-2156", "CVE-2023-2166", "CVE-2023-2985", "CVE-2023-31083", "CVE-2023-3117", "CVE-2023-31248", "CVE-2023-3268", "CVE-2023-3390", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3812", "CVE-2023-4004");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 17:08:39 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:52:15 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:3318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3318-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZK4GLO7JHBD3HY3SUMFNXXE7VOAKKMD2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:3318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security and bugfixes.

  The following security bugs were fixed:

  * CVE-2022-40982: Fixed transient execution attack called 'Gather Data
      Sampling' (bsc#1206418).

  * CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec
      (bsc#1211738).

  * CVE-2023-20569: Fixed side channel attack Inception or RAS Poisoning
      (bsc#1213287).

  * CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an
      attacker to potentially access sensitive information (bsc#1213286).

  * CVE-2023-21400: Fixed several memory corruptions due to improper locking in
      io_uring (bsc#1213272).

  * CVE-2023-2156: Fixed a flaw in the networking subsystem within the handling
      of the RPL protocol (bsc#1211131).

  * CVE-2023-2166: Fixed NULL pointer dereference in can_rcv_filter
      (bsc#1210627).

  * CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in
      fs/hfsplus/super.c that could allow a local user to cause a denial of
      service (bsc#1211867).

  * CVE-2023-31083: Fixed race condition in hci_uart_tty_ioctl (bsc#1210780).

  * CVE-2023-3117: Fixed an use-after-free vulnerability in the netfilter
      subsystem when processing named and anonymous sets in batch requests that
      could allow a local user with CAP_NET_ADMIN capability to crash or
      potentially escalate their privileges on the system (bsc#1213245).

  * CVE-2023-31248: Fixed an use-after-free vulnerability in
      nft_chain_lookup_byid that could allow a local attacker to escalate their
      privilege (bsc#1213061).

  * CVE-2023-3268: Fixed an out of bounds memory access flaw in
      relay_file_read_start_pos in the relayfs (bsc#1212502).

  * CVE-2023-3390: Fixed an use-after-free vulnerability in the netfilter
      subsystem in net/netfilter/nf_tables_api.c that could allow a local attacker
      with user access to cause a privilege escalation issue (bsc#1212846).

  * CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder
      that could allow a local attacker to escalate their privilege (bsc#1213059).

  * CVE-2023-3567: Fixed a use-after-free in vcs_read in
      drivers/tty/vt/vc_screen.c (bsc#1213167).

  * CVE-2023-3609: Fixed reference counter leak leading to overflow in net/sched
      (bsc#1213586).

  * CVE-2023-3611: Fixed an out-of-bounds write in net/sched
      sch_qfq(bsc#1213585).

  * CVE-2023-3776: Fixed improper refcount update in cls_fw leads  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.46.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.46.1", rls:"openSUSELeapMicro5.4"))) {
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