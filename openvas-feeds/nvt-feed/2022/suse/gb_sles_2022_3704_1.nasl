# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3704.1");
  script_cve_id("CVE-2020-16119", "CVE-2022-20008", "CVE-2022-2503", "CVE-2022-2586", "CVE-2022-32296", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-41218", "CVE-2022-41222", "CVE-2022-41674", "CVE-2022-41848", "CVE-2022-41849", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721");
  script_tag(name:"creation_date", value:"2022-10-25 04:56:25 +0000 (Tue, 25 Oct 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:09 +0000 (Tue, 18 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3704-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223704-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204060");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3704-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated.

The following security bugs were fixed:

- CVE-2020-16119: Fixed a use-after-free vulnerability exploitable by a local attacker due to reuse of a DCCP socket. (bnc#1177471)
- CVE-2022-20008: Fixed a bug which allowed to read kernel heap memory due to uninitialized data. This could lead to local information disclosure if reading from an SD card that triggers errors, with no additional execution privileges needed. (bnc#1199564)
- CVE-2022-2503: Fixed a bug in dm-verity, device-mapper table reloads allowed users with root privileges to switch out the target with an equivalent dm-linear target and bypass verification till reboot. This allowed root to bypass LoadPin and can be used to load untrusted and unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for peripherals that do not verify firmware updates (bnc#1202677).
- CVE-2022-2586: Fixed a use-after-free which can be triggered when a nft table is deleted (bnc#1202095).
- CVE-2022-32296: Fixed a bug which allowed TCP servers to identify clients by observing what source ports are used (bnc#1200288).
- CVE-2022-3239: Fixed an use-after-free in the video4linux driver that could lead a local user to able to crash the system or escalate their privileges (bnc#1203552).
- CVE-2022-3303: Fixed a race condition in the sound subsystem due to improper locking (bnc#1203769).
- CVE-2022-41218: Fixed an use-after-free caused by refcount races in drivers/media/dvb-core/dmxdev.c (bnc#1202960).
- CVE-2022-41222: Fixed a use-after-free via a stale TLB because an rmap lock is not held during a PUD move (bnc#1203622).
- CVE-2022-41674: Fixed a DoS issue where kernel can crash on the reception of specific WiFi Frames (bsc#1203770).
- CVE-2022-41848: Fixed a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling ioctl (bnc#1203987).
- CVE-2022-41849: Fixed a race condition and resultant use-after-free if a physically proximate attacker removes a USB device while calling open (bnc#1203992).
- CVE-2022-42719: Fixed remote code execution with wlan frames when parsing a multi-BSSID element (bsc#1204051).
- CVE-2022-42720: Fixed remote code execution due to refcounting bugs (bsc#1204059).
- CVE-2022-42721: Fixed remote code execution due list corruption in the wlan stack (bsc#1204060).

The following non-security bugs were fixed:

- net: mana: Add support of XDP_REDIRECT action (bsc#1201310, jsc#PED-529).
- net: mana: Add the Linux MANA PF driver (bsc#1201309, jsc#PED-529).
- x86/bugs: Reenable retbleed=off While for older kernels the return thunks are statically built in and cannot be dynamically patched out, retbleed=off should still work so that it can be disabled.");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.134.1.150200.9.63.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.134.1", rls:"SLES15.0SP2"))) {
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
