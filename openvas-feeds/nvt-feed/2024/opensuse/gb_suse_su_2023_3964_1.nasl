# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833614");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2007", "CVE-2023-20588", "CVE-2023-34319", "CVE-2023-3610", "CVE-2023-37453", "CVE-2023-3772", "CVE-2023-3863", "CVE-2023-4128", "CVE-2023-4133", "CVE-2023-4134", "CVE-2023-4147", "CVE-2023-4194", "CVE-2023-4273", "CVE-2023-4387", "CVE-2023-4459", "CVE-2023-4569");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 14:27:55 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:03:11 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:3964-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3964-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YA6M4OHON7SZBRFBX7PUH2GNVIUUMC2E");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:3964-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-2007: Fixed a flaw in the DPT I2O Controller driver that could
      allow an attacker to escalate privileges and execute arbitrary code in the
      context of the kernel (bsc#1210448).

  * CVE-2023-20588: Fixed a division-by-zero error on some AMD processors that
      can potentially return speculative data resulting in loss of confidentiality
      (bsc#1213927).

  * CVE-2023-34319: Fixed buffer overrun triggered by unusual packet in
      xen/netback (XSA-432) (bsc#1213546).

  * CVE-2023-3610: Fixed use-after-free vulnerability in nf_tables can be
      exploited to achieve local privilege escalation (bsc#1213580).

  * CVE-2023-37453: Fixed oversight in SuperSpeed initialization (bsc#1213123).

  * CVE-2023-3772: Fixed a flaw in XFRM subsystem that may have allowed a
      malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL
      pointer leading to a possible kernel crash and denial of service
      (bsc#1213666).

  * CVE-2023-3863: Fixed a use-after-free flaw was found in nfc_llcp_find_local
      that allowed a local user with special privileges to impact a kernel
      information leak issue (bsc#1213601).

  * CVE-2023-4128: Fixed a use-after-free flaw in net/sched/cls_fw.c that
      allowed a local attacker to perform a local privilege escalation due to
      incorrect handling of the existing filter, leading to a kernel information
      leak issue (bsc#1214149).

  * CVE-2023-4133: Fixed use after free bugs caused by circular dependency
      problem in cxgb4 (bsc#1213970).

  * CVE-2023-4134: Fixed use-after-free in cyttsp4_watchdog_work()
      (bsc#1213971).

  * CVE-2023-4147: Fixed use-after-free in nf_tables_newrule (bsc#1213968).

  * CVE-2023-4194: Fixed a type confusion in net tun_chr_open() (bsc#1214019).

  * CVE-2023-4273: Fixed a flaw in the exFAT driver of the Linux kernel that
      alloawed a local privileged attacker to overflow the kernel stack
      (bsc#1214120).

  * CVE-2023-4387: Fixed use-after-free flaw in vmxnet3_rq_alloc_rx_buf that
      could allow a local attacker to crash the system due to a double-free
      (bsc#1214350).

  * CVE-2023-4459: Fixed a NULL pointer dereference flaw in vmxnet3_rq_cleanup
      that may have allowed a local attacker with normal user privilege to cause a
      denial of service (bsc#1214451).

  * CVE-2023-4569: Fixed information leak in nft_set_catchall_flush in
      net/netfilter/nf_tables_api.c (bsc ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.53.1", rls:"openSUSELeap15.4"))) {
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