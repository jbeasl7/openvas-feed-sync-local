# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833905");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-24588", "CVE-2022-36280", "CVE-2022-4382", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0122", "CVE-2023-0179", "CVE-2023-0266", "CVE-2023-0590", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:38 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-08 02:00:53 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux (SUSE-SU-2023:0488-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0488-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JFNBOYLSAMAO6SVMONJIAEX2XKRVBV3T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux'
  package(s) announced via the SUSE-SU-2023:0488-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security and bugfixes.

  The following security bugs were fixed:

  * CVE-2022-36280: Fixed an out-of-bounds memory access vulnerability that was
      found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_kms.c (bnc#1203332).

  * CVE-2023-0045: Fixed flush IBP in ib_prctl_set() (bsc#1207773).

  * CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).

  * CVE-2023-0122: Fixed a NULL pointer dereference vulnerability in
      nvmet_setup_auth(), that allowed an attacker to perform a Pre-Auth Denial of
      Service (DoS) attack on a remote machine (bnc#1207050).

  * CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in
      net/sched/sch_atm.c because of type confusion (non-negative numbers can
      sometimes indicate a TC_ACT_SHOT condition rather than valid classification
      results) (bsc#1207125).

  * CVE-2023-23454: Fixed denial or service in cbq_classify in
      net/sched/sch_cbq.c (bnc#1207036).

  * CVE-2020-24588: Fixed injection of arbitrary network packets against devices
      that support receiving non-SSP A-MSDU frames (which is mandatory as part of
      802.11n) (bsc#1199701).

  * CVE-2023-0179: Fixed incorrect arithmetic when fetching VLAN header bits
      (bsc#1207034).

  * CVE-2022-4382: Fixed a use-after-free flaw that was caused by a race
      condition among the superblock operations inside the gadgetfs code
      (bsc#1206258).

  * CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM
      package. SNDRV_CTL_IOCTL_ELEM_{READWRITE}32 was missing locks that could
      have been used in a use-after-free that could have resulted in a privilege
      escalation to gain ring0 access from the system user (bsc#1207134).

  * CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic control
      subsystem (bnc#1207237).

  The following non-security bugs were fixed:

  * ACPI: EC: Fix EC address space handler unregistration (bsc#1207149).

  * ACPI: EC: Fix ECDT probe ordering issues (bsc#1207149).

  * ACPI: PM: s2idle: Add support for upcoming AMD uPEP HID AMDI008
      (bsc#1206224).

  * ACPI: PM: s2idle: Use LPS0 idle if ACPI_FADT_LOW_POWER_S0 is unset
      (bsc#1206224).

  * ACPI: PRM: Check whether EFI runtime is available (git-fixes).

  * ACPI: x86: s2idle: Add a quirk for ASUS ROG Zephyrus G14 (bsc#1206224).

  * ACPI: x86: s2idle: Add a quirk for ASUS TUF Gaming A17 FA707RE
      (bsc#1206224).

  * ACPI: x86: s2idle: Add a quirk for ASUSTeK COMPUTER INC. ROG Flow X1 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150400.15.11.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.11.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.11.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.11.1", rls:"openSUSELeapMicro5.3"))) {
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