# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2427.1");
  script_cve_id("CVE-2020-24588", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-33200", "CVE-2021-33624", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:52 +0000 (Thu, 29 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2427-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212427-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188116");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009190.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-22555: Fixed an heap out-of-bounds write in net/netfilter/x_tables.c that could allow local provilege escalation. (bsc#1188116)
- CVE-2021-33624: Fixed a bug which allows unprivileged BPF program to leak the contents of arbitrary kernel memory (and therefore, of all physical memory) via a side-channel. (bsc#1187554)
- CVE-2021-0605: Fixed an out-of-bounds read which could lead to local information disclosure in the kernel with System execution privileges needed. (bsc#1187601)
- CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to local escalation of privilege with no additional execution privileges needed. (bsc#1187595)
- CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing that could permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing. (bnc#1179610)
- CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local users to obtain sensitive information from kernel stack memory because parts of a data structure are uninitialized. (bsc#1187452)
- CVE-2021-0129: Fixed an improper access control in BlueZ that may have allowed an authenticated user to potentially enable information disclosure via adjacent access. (bnc#1186463)
- CVE-2020-36386: Fixed an out-of-bounds read in hci_extended_inquiry_result_evt. (bsc#1187038)
- CVE-2020-24588: Fixed a bug that could allow an adversary to abuse devices that support receiving non-SSP A-MSDU frames to inject arbitrary network packets. (bsc#1185861 bsc#1185863)
- CVE-2021-33909: Fixed an out-of-bounds write in the filesystem layer that allows to andobtain full root privileges. (bsc#1188062)
- CVE-2021-3609: Fixed a race condition in the CAN BCM networking protocol which allows for local privilege escalation. (bsc#1187215)
- CVE-2020-36385: Fixed a use-after-free flaw in ucma.c which allows for local privilege escalation. (bsc#1187050)
- CVE-2021-33200: Fix leakage of uninitialized bpf stack under speculation. (bsc#1186484)

The following non-security bugs were fixed:

- af_packet: fix the tx skb protocol in raw sockets with ETH_P_ALL (bsc#1176081).
- kabi: preserve struct header_ops after bsc#1176081 fix (bsc#1176081).
- net: Do not set transport offset to invalid value (bsc#1176081).
- net: Introduce parse_protocol header_ops callback (bsc#1176081).
- net/ethernet: Add parse_protocol header_ops support (bsc#1176081).
- net/mlx5e: Remove the wrong assumption about transport offset (bsc#1176081).
- net/mlx5e: Trust kernel regarding transport offset (bsc#1176081).
- net/packet: Ask driver for protocol if not provided by user (bsc#1176081).
- net/packet: Remove redundant skb->protocol set (bsc#1176081).
- resource: Fix find_next_iomem_res() iteration issue (bsc#1181193).
- scsi: scsi_dh_alua: Retry RTPG on a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.99.1", rls:"SLES15.0SP1"))) {
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
