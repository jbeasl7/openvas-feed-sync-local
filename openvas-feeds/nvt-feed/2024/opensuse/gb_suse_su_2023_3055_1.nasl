# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833222");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2002", "CVE-2023-2235", "CVE-2023-35788");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:21 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel RT (Live Patch 1 for SLE 15 SP4) (SUSE-SU-2023:3055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3055-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FKCTXAVCF7UPMYB4VOTJMYDE6KTB2EPC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel RT (Live Patch 1 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2023:3055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_15_5 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-35788: Fixed an out-of-bounds write in the flower classifier code
      via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets in fl_set_geneve_opt in
      net/sched/cls_flower.c (bsc#1212509).

  * CVE-2023-2235: Fixed an use-after-free in the Performance Events system can
      be exploited to achieve local privilege escalation (bsc#1210987).

  * CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized
      execution of management commands, compromising the confidentiality,
      integrity, and availability of Bluetooth communication (bsc#1210566).

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel RT (Live Patch 1 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-4", rpm:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-4~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-7", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-7", rpm:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-7", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-4", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-4~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-4", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-4~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-4", rpm:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-4~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-7", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-7", rpm:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-7", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-4", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-4~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-4", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-4~150400.2.1", rls:"openSUSELeap15.4"))) {
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