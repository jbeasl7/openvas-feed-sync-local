# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833083");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2163", "CVE-2023-3610", "CVE-2023-3777", "CVE-2023-4622", "CVE-2023-5345");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 02:02:18 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:05:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 3 for SLE 15 SP5) (SUSE-SU-2023:4848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4848-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZO5TW2WETJSM6IO2JHYI3HUDIY65PIGT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 3 for SLE 15 SP5)'
  package(s) announced via the SUSE-SU-2023:4848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150500_55_19 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-3610: Fixed use-after-free vulnerability in nf_tables can be
      exploited to achieve local privilege escalation (bsc#1213584).

  * CVE-2023-3777: Fixed a use-after-free vulnerability in netfilter: nf_tables
      component can be exploited to achieve local privilege escalation.
      (bsc#1215097)

  * CVE-2023-5345: Fixed an use-after-free vulnerability in the fs/smb/client
      component which could be exploited to achieve local privilege escalation.
      (bsc#1215971)

  * CVE-2023-4622: Fixed a use-after-free vulnerability in the Unix domain
      sockets component which could be exploited to achieve local privilege
      escalation (bsc#1215442).

  * CVE-2023-2163: Fixed an incorrect verifier pruning in BPF that could lead to
      unsafe code paths being incorrectly marked as safe, resulting in arbitrary
      read/write in kernel memory, lateral privilege escalation, and container
      escape. (bsc#1215519)

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 3 for SLE 15 SP5)' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_14-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_14-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-12", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_13-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_13-debugsource-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-12", rpm:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_69-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_69-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_66-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_66-default-debuginfo-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_66-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_66-default-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-12", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_69-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_69-default-debuginfo-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-10~150400.2.2##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_14-debugsource-5", rpm:"kernel-livepatch-SLE15-SP4_Update_14-debugsource-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-debuginfo-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-10", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-12", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-debuginfo-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_13-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_13-debugsource-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-12", rpm:"kernel-livepatch-SLE15-SP4_Update_6-debugsource-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_10-debugsource-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_69-default-5", rpm:"kernel-livepatch-5_14_21-150400_24_69-default-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_66-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_66-default-debuginfo-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-10", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-10~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_66-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_66-default-6~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_55-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_55-default-9~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_38-default-12", rpm:"kernel-livepatch-5_14_21-150400_24_38-default-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_69-default-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150400_24_69-default-debuginfo-5~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-10", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-10~150400.2.2##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_19-default-4", rpm:"kernel-livepatch-5_14_21-150500_55_19-default-4~150500.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5_Update_3-debugsource-4", rpm:"kernel-livepatch-SLE15-SP5_Update_3-debugsource-4~150500.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_19-default-debuginfo-4", rpm:"kernel-livepatch-5_14_21-150500_55_19-default-debuginfo-4~150500.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_19-default-4", rpm:"kernel-livepatch-5_14_21-150500_55_19-default-4~150500.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5_Update_3-debugsource-4", rpm:"kernel-livepatch-SLE15-SP5_Update_3-debugsource-4~150500.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_55_19-default-debuginfo-4", rpm:"kernel-livepatch-5_14_21-150500_55_19-default-debuginfo-4~150500.2.1", rls:"openSUSELeap15.5"))) {
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