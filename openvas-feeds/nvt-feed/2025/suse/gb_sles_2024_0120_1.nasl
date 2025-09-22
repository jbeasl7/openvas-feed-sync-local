# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0120.1");
  script_cve_id("CVE-2020-26555", "CVE-2022-2586", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 16:21:26 +0000 (Fri, 12 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0120-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240120-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218559");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017659.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-26555: Fixed Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B that may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN (bsc#1179610 bsc#1215237).
- CVE-2022-2586: Fixed a use-after-free which can be triggered when a nft table is deleted (bsc#1202095).
- CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
- CVE-2023-6121: Fixed an out-of-bounds read vulnerability in the NVMe-oF/TCP subsystem that could lead to information leak (bsc#1217250).
- CVE-2023-6606: Fixed an out-of-bounds read vulnerability in smbCalcSize in fs/smb/client/netmisc.c that could allow a local attacker to crash the system or leak internal kernel information (bsc#1217947).
- CVE-2023-6610: Fixed an out-of-bounds read vulnerability in smb2_dump_detail in fs/smb/client/smb2ops.c that could allow a local attacker to crash the system or leak internal kernel information (bsc#1217946).
- CVE-2023-6931: Fixed a heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component that could lead to local privilege escalation. (bsc#1218258).
- CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's ipv4: igmp component that could lead to local privilege escalation (bsc#1218253).

The following non-security bugs were fixed:

- doc/README.SUSE: Add how to update the config for module signing (jsc#PED-5021)
- doc/README.SUSE: Remove how to build modules using kernel-source (jsc#PED-5021)
- doc/README.SUSE: Simplify the list of references (jsc#PED-5021)");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150100.197.168.1", rls:"SLES15.0SP1"))) {
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
