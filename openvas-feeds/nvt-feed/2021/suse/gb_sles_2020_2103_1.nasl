# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2103.1");
  script_cve_id("CVE-2019-20810", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-10781", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-13974", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:58 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-24 17:31:00 +0000 (Fri, 24 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2103-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202103-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-15393: Fixed a memory leak in usbtest_disconnect (bnc#1173514).

CVE-2020-12771: An issue was discovered in btree_gc_coalesce in
 drivers/md/bcache/btree.c has a deadlock if a coalescing operation fails
 (bnc#1171732).

CVE-2020-12888: The VFIO PCI driver mishandled attempts to access
 disabled memory space (bnc#1171868).

CVE-2020-10773: Fixed a memory leak on s390/s390x, in the
 cmm_timeout_hander in file arch/s390/mm/cmm.c (bnc#1172999).

CVE-2020-14416: Fixed a race condition in tty->disc_data handling in the
 slip and slcan line discipline could lead to a use-after-free. This
 affects drivers/net/slip/slip.c and drivers/net/can/slcan.c
 (bnc#1162002).

CVE-2020-10768: Fixed an issue with the prctl() function, where indirect
 branch speculation could be enabled even though it was diabled before
 (bnc#1172783).

CVE-2020-10766: Fixed an issue which allowed an attacker with a local
 account to disable SSBD protection (bnc#1172781).

CVE-2020-10767: Fixed an issue where Indirect Branch Prediction Barrier
 was disabled in certain circumstances, leaving the system open to a
 spectre v2 style attack (bnc#1172782).

CVE-2020-13974: Fixed a integer overflow in drivers/tty/vt/keyboard.c,
 if k_ascii is called several times in a row (bnc#1172775).

CVE-2019-20810: Fixed a memory leak in go7007_snd_init in
 drivers/media/usb/go7007/snd-go7007.c because it did not call
 snd_card_free for a failure path (bnc#1172458).

CVE-2020-10769: A buffer over-read flaw was found in
 crypto_authenc_extractkeys in crypto/authenc.c in the IPsec
 Cryptographic algorithm's module, authenc. This flaw allowed a local
 attacker with user privileges to cause a denial of service (bnc#1173265).

CVE-2020-10781: Fixed a denial of service issue in the ZRAM
 implementation (bsc#1173074).

CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
 use-after-free due to a race condition. This could lead to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bsc#1174462).

CVE-2019-20908: An issue was discovered in drivers/firmware/efi/efi.c:
 incorrect access permissions for the efivar_ssdt ACPI variable could be
 used by attackers to bypass lockdown or secure boot restrictions, aka
 CID-1957a85b0032 (bsc#1173567).

CVE-2020-15780: An issue was discovered in drivers/acpi/acpi_configfs.c:
 injection of malicious ACPI tables via configfs could be used by
 attackers to bypass lockdown and secure boot restrictions, aka
 CID-75b0cea7bf30 (bsc#1173573).

The following non-security bugs were fixed:

ACPI: GED: add support for _Exx / _Lxx handler methods (bsc#1111666).

ACPI: GED: use correct trigger type field in _Exx / _Lxx handling
 (bsc#1111666).

ACPI: NFIT: Fix unlock on error in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.38.1", rls:"SLES15.0SP1"))) {
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
