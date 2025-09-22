# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2406.1");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:52 +0000 (Thu, 29 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2406-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212406-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188116");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009166.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-22555: Fixed an heap out-of-bounds write in net/netfilter/x_tables.c that could allow local provilege escalation. (bsc#1188116)
- CVE-2021-33909: Fixed an out-of-bounds write in the filesystem layer that allows to obtain full root privileges. (bsc#1188062)
- CVE-2021-3609: Fixed a race condition in the CAN BCM networking protocol which allows for local privilege escalation. (bsc#1187215)
- CVE-2021-0605: Fixed an out-of-bounds read which could lead to local information disclosure in the kernel with System execution privileges needed. (bsc#1187601)
- CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to local escalation of privilege with no additional execution privileges needed. (bsc#1187595)
- CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local users to obtain sensitive information from kernel stack memory because parts of a data structure are uninitialized. (bsc#1187452)
- CVE-2020-36385: Fixed a use-after-free flaw in ucma.c which allows for local privilege escalation. (bsc#1187050)
- CVE-2021-0129: Fixed an improper access control in BlueZ that may have allowed an authenticated user to potentially enable information disclosure via adjacent access. (bsc#1186463)
- CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing that could permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing. (bsc#1179610)
- CVE-2020-36386: Fixed an out-of-bounds read in hci_extended_inquiry_result_evt. (bsc#1187038)
- CVE-2020-24588: Fixed a bug that could allow an adversary to abuse devices that support receiving non-SSP A-MSDU frames to inject arbitrary network packets. (bsc#1185861)
- CVE-2021-32399: Fixed a race condition in net/bluetooth/hci_request.c for removal of the HCI controller. (bsc#1184611)
- CVE-2021-33034: Fixed an issue in net/bluetooth/hci_event.c where a use-after-free leads to writing an arbitrary value. (bsc#1186111)
- CVE-2020-26139: Fixed a bug that allows an Access Point (AP) to forward EAPOL frames to other clients even though the sender has not yet successfully authenticated. This might be abused in projected Wi-Fi networks to launch denial-of-service attacks against connected clients and made it easier to exploit other vulnerabilities in connected clients. (bsc#1186062)
- CVE-2021-23134: Fixed a use After Free vulnerability in nfc sockets which allows local attackers to elevate their privileges. (bsc#1186060)
- CVE-2020-24586: Fixed a bug that, under the right circumstances, allows to inject arbitrary network packets and/or exfiltrate user data when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP. (bsc#1185859)
- CVE-2020-26141: Fixed a flaw that could allows an adversary to inject and possibly decrypt packets ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.158.1", rls:"SLES12.0SP2"))) {
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
