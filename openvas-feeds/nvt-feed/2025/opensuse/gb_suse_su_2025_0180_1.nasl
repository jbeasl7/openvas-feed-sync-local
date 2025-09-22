# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856967");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2022-48956", "CVE-2024-50264");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-21 19:28:21 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"creation_date", value:"2025-01-21 05:00:04 +0000 (Tue, 21 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 49 for SLE 15 SP3) (SUSE-SU-2025:0180-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0180-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MNAI73U63KCJKEVCBQFJNRHVS52PUTO2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 49 for SLE 15 SP3)'
  package(s) announced via the SUSE-SU-2025:0180-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.3.18-150300_59_179 fixes several issues.

  The following security issues were fixed:

  * CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer
      occurring in vsk->trans (bsc#1233712).

  * CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1232637).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 49 for SLE 15 SP3)' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP3_Update_49-debugsource-2", rpm:"kernel-livepatch-SLE15-SP3_Update_49-debugsource-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_174-default-debuginfo-2", rpm:"kernel-livepatch-5_3_18-150300_59_174-default-debuginfo-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_179-default-2", rpm:"kernel-livepatch-5_3_18-150300_59_179-default-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_174-default-2", rpm:"kernel-livepatch-5_3_18-150300_59_174-default-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP3_Update_48-debugsource-2", rpm:"kernel-livepatch-SLE15-SP3_Update_48-debugsource-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_179-default-debuginfo-2", rpm:"kernel-livepatch-5_3_18-150300_59_179-default-debuginfo-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_174-preempt-debuginfo-2", rpm:"kernel-livepatch-5_3_18-150300_59_174-preempt-debuginfo-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_179-preempt-2", rpm:"kernel-livepatch-5_3_18-150300_59_179-preempt-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_174-preempt-2", rpm:"kernel-livepatch-5_3_18-150300_59_174-preempt-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_179-preempt-debuginfo-2", rpm:"kernel-livepatch-5_3_18-150300_59_179-preempt-debuginfo-2~150300.7.6.1", rls:"openSUSELeap15.3"))) {
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