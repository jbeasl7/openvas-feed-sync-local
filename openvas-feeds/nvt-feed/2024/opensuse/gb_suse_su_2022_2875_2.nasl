# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833810");
  script_version("2025-02-26T05:38:40+0000");
  script_cve_id("CVE-2020-36516", "CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1116", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-21505", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-2639", "CVE-2022-29581", "CVE-2022-32250", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-36946");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:56 +0000 (Sun, 12 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:50:08 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2022:2875-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2875-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NOR2NSDGCLTFWRJP6GDPDSOOED3ZEFM3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2022:2875-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various
     security and bugfixes.
  The following security bugs were fixed:

  - CVE-2020-36516: Fixed TCP session data injection vulnerability via the
       mixed IPID assignment method (bnc#1196616).

  - CVE-2020-36557: Fixed race condition between the VT_DISALLOCATE ioctl
       and closing/opening of ttys that could lead to a use-after-free
       (bnc#1201429).

  - CVE-2020-36558: Fixed race condition involving VT_RESIZEX that could
       lead to a NULL pointer dereference and general protection fault
       (bnc#1200910).

  - CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
       (bnc#1201635).

  - CVE-2021-33656: Fixed out of bounds write with ioctl PIO_FONT
       (bnc#1201636).

  - CVE-2022-1116: Fixed a integer overflow vulnerability in io_uring which
       allowed a local attacker to cause memory corruption and escalate
       privileges to root (bnc#1199647).

  - CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe
       subsystem (bnc#1198829).

  - CVE-2022-2318: Fixed a use-after-free vulnerability in the timer
       handler in net/rose/rose_timer.c that allow attackers to crash the
       system without any privileges (bsc#1201251).

  - CVE-2022-2639: Fixed integer underflow that could lead to out-of-bounds
       write in reserve_sfa_size() (bsc#1202154).

  - CVE-2022-20166: Fixed possible out of bounds write due to sprintf
       unsafety that could cause local escalation of privilege (bnc#1200598)

  - CVE-2022-21505: Fixed kexec lockdown bypass with IMA policy
       (bsc#1201458).

  - CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed
       multiple potential data leaks with Block and Network devices when using
       untrusted backends (bsc#1200762).

  - CVE-2022-29581: Fixed improper update of Reference Count in net/sched
       that could cause root privilege escalation (bnc#1199665).

  - CVE-2022-32250: Fixed user-after-free in net/netfilter/nf_tables_api.c
       that could allow local privilege escalation (bnc#1200015).

  - CVE-2022-36946: Fixed incorrect packet truncation in nfqnl_mangle() that
       could lead to remote DoS (bnc#1201940).
  The following non-security bugs were fixed:

  - ACPI: APEI: Better fix to avoid spamming the console with old error logs
       (git-fixes).

  - ACPI: CPPC: Do not prevent CPPC from working in the future (git-fixes).

  - ACPI: video: Shortening quirk list by identifying Clevo by board_name

   Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"the Linux Kernel package(s) on openSUSE Leap Micro 5.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.90.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.90.1.150300.18.52.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.90.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.90.1", rls:"openSUSELeapMicro5.2"))) {
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
