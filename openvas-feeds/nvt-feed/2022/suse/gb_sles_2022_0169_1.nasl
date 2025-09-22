# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0169.1");
  script_cve_id("CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4149", "CVE-2021-4197", "CVE-2021-4202", "CVE-2021-45485", "CVE-2021-45486", "CVE-2021-46283", "CVE-2022-0185", "CVE-2022-0322");
  script_tag(name:"creation_date", value:"2022-01-26 07:40:11 +0000 (Wed, 26 Jan 2022)");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 19:18:53 +0000 (Tue, 22 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0169-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0169-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220169-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0169-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-0185: Incorrect param length parsing in legacy_parse_param
 which could have led to a local privilege escalation (bsc#1194517).

CVE-2022-0322: Fixed a denial of service in SCTP sctp_addto_chunk
 (bsc#1194985).

CVE-2021-4197: Fixed a cgroup issue where lower privileged processes
 could write to fds of lower privileged ones that could lead to privilege
 escalation (bsc#1194302).

CVE-2021-46283: nf_tables_newset in net/netfilter/nf_tables_api.c in the
 Linux kernel allowed local users to cause a denial of service (NULL
 pointer dereference and general protection fault) because of the missing
 initialization for nft_set_elem_expr_alloc. A local user can set a
 netfilter table expression in their own namespace (bnc#1194518).

CVE-2021-4135: Fixed an information leak in the nsim_bpf_map_alloc
 function (bsc#1193927).

CVE-2021-4202: Fixed a race condition during NFC device remove which
 could lead to a use-after-free memory corruption (bsc#1194529)

CVE-2021-4083: A read-after-free memory flaw was found in the Linux
 kernel's garbage collection for Unix domain socket file handlers in the
 way users call close() and fget() simultaneously and can potentially
 trigger a race condition. This flaw allowed a local user to crash the
 system or escalate their privileges on the system. (bnc#1193727).

CVE-2021-4149: Fixed a locking condition in btrfs which could lead to
 system deadlocks (bsc#1194001).

CVE-2021-45485: In the IPv6 implementation net/ipv6/output_core.c has an
 information leak because of certain use of a hash table which, although
 big, doesn't properly consider that IPv6-based attackers can typically
 choose among many IPv6 source addresses (bnc#1194094).

CVE-2021-45486: In the IPv4 implementation net/ipv4/route.c has an
 information leak because the hash table is very small (bnc#1194087).

The following non-security bugs were fixed:

ACPI: APD: Check for NULL pointer after calling devm_ioremap()
 (git-fixes).

ACPI: Add stubs for wakeup handler functions (git-fixes).

ACPI: scan: Create platform device for BCM4752 and LNV4752 ACPI nodes
 (git-fixes).

ALSA: PCM: Add missing rwsem around snd_ctl_remove() calls (git-fixes).

ALSA: ctl: Fix copy of updated id with element read/write (git-fixes).

ALSA: drivers: opl3: Fix incorrect use of vp->state (git-fixes).

ALSA: hda/hdmi: Disable silent stream on GLK (git-fixes).

ALSA: hda/realtek - Add headset Mic support for Lenovo ALC897 platform
 (git-fixes).

ALSA: hda/realtek - Fix silent output on Gigabyte X570 Aorus Master
 after reboot from Windows (git-fixes).

ALSA: hda/realtek: Add a quirk for HP OMEN 15 mute LED (git-fixes).

ALSA: hda/realtek: Add quirk for ASRock NUC Box 1100 (git-fixes).

ALSA: hda/realtek: Amp init fixup for HP ZBook 15 G6 (git-fixes).

ALSA: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.37.1", rls:"SLES15.0SP3"))) {
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
