# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833573");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2019-19377", "CVE-2020-26541", "CVE-2021-33061", "CVE-2022-0168", "CVE-2022-1184", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-20008", "CVE-2022-20141", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-30594", "CVE-2022-32250");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:56 +0000 (Sun, 12 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:53:31 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (openSUSE-SU-2022:2177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:2177-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/S2QMD6CJ6PZDFYQ3RKSOGAZNRK7WC5W7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the openSUSE-SU-2022:2177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated.
  The following security bugs were fixed:

  - CVE-2022-1972: Fixed a buffer overflow in nftable that could lead to
       privilege escalation. (bsc#1200019)

  - CVE-2019-19377: Fixed an user-after-free that could be triggered when an
       attacker mounts a crafted btrfs filesystem image. (bnc#1158266)

  - CVE-2022-1729: Fixed a sys_perf_event_open() race condition against self
       (bsc#1199507).

  - CVE-2022-1184: Fixed an use-after-free and memory errors in ext4 when
       mounting and operating on a corrupted image. (bsc#1198577)

  - CVE-2022-1652: Fixed a statically allocated error counter inside the
       floppy kernel module (bsc#1199063).

  - CVE-2022-20008: Fixed bug that allows to read kernel heap memory due to
       uninitialized data in mmc_blk_read_single of block.c. (bnc#1199564)

  - CVE-2022-30594: Fixed restriction bypass on setting the
       PT_SUSPEND_SECCOMP flag (bnc#1199505).

  - CVE-2022-0168: Fixed a NULL pointer dereference in
       smb2_ioctl_query_info. (bsc#1197472)

  - CVE-2021-33061: Fixed insufficient control flow management for the
       Intel(R) 82599 Ethernet Controllers and Adapters that may have allowed
       an authenticated user to potentially enable denial of service via local
       access (bnc#1196426).

  - CVE-2022-20141: Fixwed an use after free due to improper locking. This
       bug could lead to local escalation of privilege when opening and closing
       inet sockets with no additional execution privileges needed.
       (bnc#1200604)

  - CVE-2022-21123: Fixed a stale MMIO data transient which can be exploited
       to speculatively/transiently disclose information via spectre like
       attacks. (bsc#1199650)

  - CVE-2022-21125: Fixed a stale MMIO data transient which can be exploited
       to speculatively/transiently disclose information via spectre like
       attacks. (bsc#1199650)

  - CVE-2022-21180: Fixed a stale MMIO data transient which can be exploited
       to speculatively/transiently disclose information via spectre like
       attacks. (bsc#1199650)

  - CVE-2022-21166: Fixed a stale MMIO data transient which can be exploited
       to speculatively/transiently disclose information via spectre like
       attacks. (bsc#1199650)

  - CVE-2022-21127: Fixed a stale MMIO data transient which can be exploited
       to speculatively/transiently disclose information via spectre like
       attacks. (bsc#1199650)

  - CVE-2022-1975: Fixed a sleep-in-atomic bug that allows attacker to crash
       linux k ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.93.1", rls:"openSUSELeapMicro5.2"))) {
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