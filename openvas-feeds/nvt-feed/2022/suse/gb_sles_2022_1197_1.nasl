# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1197.1");
  script_cve_id("CVE-2021-0920", "CVE-2021-39698", "CVE-2021-45868", "CVE-2022-0850", "CVE-2022-0854", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-1055", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27666", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-04-15 04:28:02 +0000 (Fri, 15 Apr 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:28:24 +0000 (Sat, 09 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1197-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1197-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221197-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198033");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010731.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1197-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated.

The following security bugs were fixed:

- CVE-2021-45868: Fixed a wrong validation check in fs/quota/quota_tree.c which could lead to an use-after-free if there is a corrupted quota file. (bnc#1197366)
- CVE-2022-27666: Fixed a buffer overflow vulnerability in IPsec ESP transformation code. This flaw allowed a local attacker with a normal user privilege to overwrite kernel heap objects and may cause a local privilege escalation. (bnc#1197462)
- CVE-2022-0850: Fixed a kernel information leak vulnerability in iov_iter.c. (bsc#1196761)
- CVE-2022-1055: Fixed a use-after-free in tc_new_tfilter that could allow a local attacker to gain privilege escalation. (bnc#1197702)
- CVE-2022-1048: Fixed a race Condition in snd_pcm_hw_free leading to use-after-free due to the AB/BA lock with buffer_mutex and mmap_lock. (bsc#1197331)
- CVE-2022-28390: Fixed a double free in drivers/net/can/usb/ems_usb.c vulnerability in the Linux kernel. (bnc#1198031)
- CVE-2022-28388: Fixed a double free in drivers/net/can/usb/usb_8dev.c vulnerability in the Linux kernel. (bnc#1198032)
- CVE-2022-28389: Fixed a double free in drivers/net/can/usb/mcba_usb.c vulnerability in the Linux kernel. (bnc#1198033)
- CVE-2022-1016: Fixed a vulnerability in the nf_tables component of the netfilter subsystem. This vulnerability gives an attacker a powerful primitive that can be used to both read from and write to relative stack data, which can lead to arbitrary code execution. (bsc#1197227)
- CVE-2022-0854: Fixed a memory leak flaw was found in the Linux kernels DMA subsystem. This flaw allowed a local user to read random memory from the kernel space. (bnc#1196823)
- CVE-2022-26966: Fixed an issue in drivers/net/usb/sr9700.c, which allowed attackers to obtain sensitive information from the memory via crafted frame lengths from a USB device. (bsc#1196836)
- CVE-2021-39698: Fixed a possible memory corruption due to a use after free in aio_poll_complete_work. This could lead to local escalation of privilege with no additional execution privileges needed. (bsc#1196956)
- CVE-2021-0920: Fixed a race condition during UNIX socket garbage collection that could lead to local privilege escalation. (bsc#119373)
- CVE-2022-23036,CVE-2022-23037,CVE-2022-23038,CVE-2022-23039,CVE-2022-23040,CVE-2022-23041,CVE-2022-23042: Fixed multiple issues which could have lead to read/write access to memory pages or denial of service. These issues are related to the Xen PV device frontend drivers. (bsc#1196488)
- CVE-2022-26490: Fixed a buffer overflow in the st21nfca driver. An attacker with adjacent NFC access could crash the system or corrupt the system memory. (bsc#1196830)

The following non-security bugs were fixed:

- ax88179_178a: Merge memcpy + le32_to_cpus to get_unaligned_le32 (bsc#1196018).
- cifs: use the correct max-length for dentry_path_raw() (bsc1196196).
- drm: add a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.112.1.150200.9.52.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.112.1", rls:"SLES15.0SP2"))) {
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
