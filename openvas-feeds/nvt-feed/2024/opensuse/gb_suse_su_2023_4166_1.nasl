# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833482");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-3390", "CVE-2023-4004", "CVE-2023-4147", "CVE-2023-4623");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-11 18:15:49 +0000 (Mon, 11 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:24:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel RT (Live Patch 5 for SLE 15 SP4) (SUSE-SU-2023:4166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4166-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6SAW7DXMMSQO2O7C2SA5DHEZAKYC7VGC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel RT (Live Patch 5 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2023:4166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_15_18 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-4147: Fixed use-after-free in nf_tables_newrule (bsc#1215118).

  * CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler
      which could be exploited to achieve local privilege escalation
      (bsc#1215440).

  * CVE-2023-4004: Fixed improper element removal netfilter nft_set_pipapo
      (bsc#1214812).

  * CVE-2023-3390: Fixed an use-after-free vulnerability in the netfilter
      subsystem in net/netfilter/nf_tables_api.c that could allow a local attacker
      with user access to cause a privilege escalation issue (bsc#1212934).

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel RT (Live Patch 5 for SLE 15 SP4)' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_11-rt-5", rpm:"kernel-livepatch-5_14_21-150500_11-rt-5~150500.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_11-rt-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150500_11-rt-debuginfo-5~150500.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_0-debugsource-5", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_0-debugsource-5~150500.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_11-rt-5", rpm:"kernel-livepatch-5_14_21-150500_11-rt-5~150500.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150500_11-rt-debuginfo-5", rpm:"kernel-livepatch-5_14_21-150500_11-rt-debuginfo-5~150500.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP5-RT_Update_0-debugsource-5", rpm:"kernel-livepatch-SLE15-SP5-RT_Update_0-debugsource-5~150500.12.2", rls:"openSUSELeap15.5"))) {
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