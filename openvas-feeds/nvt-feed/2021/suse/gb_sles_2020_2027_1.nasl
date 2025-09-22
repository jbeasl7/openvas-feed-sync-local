# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2027.1");
  script_cve_id("CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20812", "CVE-2020-10711", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10773", "CVE-2020-12656", "CVE-2020-12769", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-13143", "CVE-2020-13974", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-24 17:31:00 +0000 (Fri, 24 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2027-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202027-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-15780: A lockdown bypass for loading unsigned modules using
 ACPI table injection was fixed. (bsc#1173573)

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

CVE-2019-20812: An issue was discovered in the prb_calc_retire_blk_tmo()
 function in net/packet/af_packet.c could result in a denial of service
 (CPU consumption and soft lockup) in a certain failure case involving
 TPACKET_V3 (bnc#1172453).

CVE-2019-19462: relay_open in kernel/relay.c in the Linux kernel allowed
 local users to cause a denial of service (such as relay blockage) by
 triggering a NULL alloc_percpu result (bnc#1158265).

CVE-2020-10732: A flaw was found in the implementation of Userspace core
 dumps. This flaw allowed an attacker with a local account to crash a
 trivial program and exfiltrate private kernel data (bnc#1171220).

CVE-2020-12656: Fixed a memory leak in gss_mech_free in the
 rpcsec_gss_krb5 implementation, caused by a lack of certain
 domain_release calls (bnc#1171219).

CVE-2020-10751: A flaw was found in the SELinux LSM hook implementation,
 where it incorrectly assumed that an skb would only contain a single
 netlink message. The hook would incorrectly only validate the first
 netlink message in the skb and allow or deny the rest of the messages
 within the skb with the granted permission without further processing
 (bnc#1171189).

CVE-2020-10711: A NULL pointer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.5.1", rls:"SLES15.0SP2"))) {
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
