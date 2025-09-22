# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2421.1");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-33624", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3491", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 19:12:55 +0000 (Fri, 11 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2421-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2421-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212421-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186111");
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
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009183.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2421-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2021-22555: A heap out-of-bounds write was discovered in net/netfilter/x_tables.c (bnc#1188116 ).
- CVE-2021-33909: Extremely large seq buffer allocations in seq_file could lead to buffer underruns and code execution (bsc#1188062).
- CVE-2021-3609: A use-after-free in can/bcm could have led to privilege escalation (bsc#1187215).
- CVE-2021-33624: In kernel/bpf/verifier.c a branch can be mispredicted (e.g., because of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a side-channel attack, aka CID-9183671af6db (bnc#1187554).
- CVE-2021-0605: In pfkey_dump of af_key.c, there is a possible out-of-bounds read due to a missing bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation (bnc#1187601).
- CVE-2021-0512: In __hidinput_change_resolution_multipliers of hid-input.c, there is a possible out of bounds write due to a heap buffer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation (bnc#1187595).
- CVE-2020-26558: Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 may permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication procedure) by reflection of the public key and the authentication evidence of the initiating device, potentially permitting this attacker to complete authenticated pairing with the responding device using the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit at a time (bnc#1179610).
- CVE-2021-34693: net/can/bcm.c in the Linux kernel allowed local users to obtain sensitive information from kernel stack memory because parts of a data structure are uninitialized (bnc#1187452).
- CVE-2020-36385: An issue was discovered in the Linux kernel drivers/infiniband/core/ucma.c has a use-after-free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is called, aka CID-f5449e74802c (bnc#1187050).
- CVE-2021-0129: Improper access control in BlueZ may have allowed an authenticated user to potentially enable information disclosure via adjacent access (bnc#1186463).
- CVE-2020-36386: An issue was discovered in the Linux kernel net/bluetooth/hci_event.c has a slab out-of-bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf (bnc#1187038).
- CVE-2020-24588: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.75.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.75.1", rls:"SLES15.0"))) {
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
