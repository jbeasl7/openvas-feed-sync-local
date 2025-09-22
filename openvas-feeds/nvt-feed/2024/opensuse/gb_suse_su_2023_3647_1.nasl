# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833620");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1077", "CVE-2023-2156", "CVE-2023-2176", "CVE-2023-3090", "CVE-2023-32233", "CVE-2023-35001");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 16:49:52 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:02:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 11 for SLE 15 SP4) (SUSE-SU-2023:3647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3647-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BGK2ZEJKJWVCK4PDHLXSGIVJCMAHNQB5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 11 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2023:3647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_24_60 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-32233: Fixed a use-after-free in Netfilter nf_tables when
      processing batch requests (bsc#1211187).

  * CVE-2023-2156: Fixed a flaw in the networking subsystem within the handling
      of the RPL protocol (bsc#1211395).

  * CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder
      that could allow a local attacker to escalate their privilege (bsc#1213063).

  * CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could
      cause memory corruption (bsc#1208839).

  * CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in
      drivers/infiniband/core/cma.c in RDMA (bsc#1210630).

  * CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver
      (bsc#1212849).

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 11 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-5~150400.2.1##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_11-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_60-default-debuginfo-5~150400.2.1##", rls:"openSUSELeap15.4"))) {
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