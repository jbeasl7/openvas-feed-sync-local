# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857002");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-36971");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-12 15:43:28 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2025-01-28 05:05:15 +0000 (Tue, 28 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 22 for SLE 15 SP4) (SUSE-SU-2025:0250-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0250-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AQTGLHTGLH5FGDDI3VYMY36ORJPN374Q");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 22 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2025:0250-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_24_103 fixes one issue.

  The following security issue was fixed:

    * CVE-2024-36971: Fixed __dst_negative_advice() race (bsc#1226324).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 22 for SLE 15 SP4)' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_103-default-14", rpm:"kernel-livepatch-5_14_21-150400_24_103-default-14~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_103-default-debuginfo-14", rpm:"kernel-livepatch-5_14_21-150400_24_103-default-debuginfo-14~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_22-debugsource-14", rpm:"kernel-livepatch-SLE15-SP4_Update_22-debugsource-14~150400.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_147-default-debuginfo-16", rpm:"kernel-livepatch-5_3_18-150300_59_147-default-debuginfo-16~150300.2.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_147-default-16", rpm:"kernel-livepatch-5_3_18-150300_59_147-default-16~150300.2.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP3_Update_40-debugsource-16", rpm:"kernel-livepatch-SLE15-SP3_Update_40-debugsource-16~150300.2.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_147-preempt-debuginfo-16", rpm:"kernel-livepatch-5_3_18-150300_59_147-preempt-debuginfo-16~150300.2.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_147-preempt-16", rpm:"kernel-livepatch-5_3_18-150300_59_147-preempt-16~150300.2.1", rls:"openSUSELeap15.3"))) {
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
