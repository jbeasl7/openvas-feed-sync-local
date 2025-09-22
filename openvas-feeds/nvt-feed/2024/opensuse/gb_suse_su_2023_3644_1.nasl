# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833692");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1077", "CVE-2023-2156", "CVE-2023-2176", "CVE-2023-3090", "CVE-2023-32233", "CVE-2023-35001", "CVE-2023-3567");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 16:49:52 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:15:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 8 for SLE 15 SP4) (SUSE-SU-2023:3644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3644-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/23WVJOFOHEBC44NO4WGX4VHK4UVJCV7K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 8 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2023:3644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_24_46 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-32233: Fixed a use-after-free in Netfilter nf_tables when
      processing batch requests (bsc#1211187).

  * CVE-2023-2156: Fixed a flaw in the networking subsystem within the handling
      of the RPL protocol (bsc#1211395).

  * CVE-2023-3567: Fixed a use-after-free in vcs_read in
      drivers/tty/vt/vc_screen.c (bsc#1213244).

  * CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder
      that could allow a local attacker to escalate their privilege (bsc#1213063).

  * CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could
      cause memory corruption (bsc#1208839).

  * CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in
      drivers/infiniband/core/cma.c in RDMA (bsc#1210630).

  * CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver
      (bsc#1212849).

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 8 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-11", rpm:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-13", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-11", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_18-default-debuginfo-14", rpm:"kernel-livepatch-5_14_21-150400_24_18-default-debuginfo-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-13", rpm:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-8", rpm:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-8~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-8", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-8~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-13", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_2-debugsource-14", rpm:"kernel-livepatch-SLE15-SP4_Update_2-debugsource-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-7", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_18-default-14", rpm:"kernel-livepatch-5_14_21-150400_24_18-default-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-11", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-7", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-7", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-8", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-8~150400.2.2##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-11", rpm:"kernel-livepatch-SLE15-SP4_Update_4-debugsource-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-13", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-11", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_18-default-debuginfo-14", rpm:"kernel-livepatch-5_14_21-150400_24_18-default-debuginfo-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-13", rpm:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-8", rpm:"kernel-livepatch-SLE15-SP4_Update_7-debugsource-8~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-8", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-8~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-13", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-13~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_2-debugsource-14", rpm:"kernel-livepatch-SLE15-SP4_Update_2-debugsource-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-7", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_18-default-14", rpm:"kernel-livepatch-5_14_21-150400_24_18-default-14~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-11", rpm:"kernel-livepatch-5_14_21-150400_24_28-default-debuginfo-11~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-7", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-7", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-7~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-8", rpm:"kernel-livepatch-5_14_21-150400_24_41-default-debuginfo-8~150400.2.2##", rls:"openSUSELeap15.4"))) {
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