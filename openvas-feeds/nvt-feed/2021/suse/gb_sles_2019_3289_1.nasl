# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3289.1");
  script_cve_id("CVE-2019-0154", "CVE-2019-0155", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19543");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 14:55:37 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3289-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193289-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel-azure was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-19531: Fixed a use-after-free due to a malicious USB device in
 the drivers/usb/misc/yurex.c driver, aka CID-fc05481b2fca (bsc#1158445).

CVE-2019-19543: Fixed a use-after-free in serial_ir_init_module() in
 drivers/media/rc/serial_ir.c (bsc#1158427).

CVE-2019-19525: Fixed a use-after-free due to a malicious USB device in
 the drivers/net/ieee802154/atusb.c driver, aka CID-7fd25e6fc035
 (bsc#1158417).

CVE-2019-19530: Fixed a use-after-free due to a malicious USB device in
 the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef
 (bsc#1158410).

CVE-2019-19536: Fixed a potential information leak due to a malicious
 USB device in the drivers/net/can/usb/peak_usb/pcan_usb_pro.c driver,
 aka CID-ead16e53c2f0 (bsc#1158394).

CVE-2019-19524: Fixed a use-after-free due to a malicious USB device in
 the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9
 (bsc#1158413).

CVE-2019-19528: Fixed a use-after-free due to a malicious USB device in
 the drivers/usb/misc/iowarrior.c driver, aka CID-edc4746f253d
 (bsc#1158407).

CVE-2019-19534: Fixed a potential information leak due to a malicious
 USB device in the drivers/net/can/usb/peak_usb/pcan_usb_core.c driver,
 aka CID-f7a1337f0d29 (bsc#1158398).

CVE-2019-19529: Fixed a use-after-free due to a malicious USB device in
 the drivers/net/can/usb/mcba_usb.c driver, aka CID-4d6636498c41
 (bsc#1158381).

CVE-2019-14901: Fixed a heap overflow in Marvell WiFi chip driver which
 could have allowed a remote attacker to cause denial of service or
 execute arbitrary code (bsc#1157042).

CVE-2019-14895: Fixed a heap-based buffer overflow in Marvell WiFi chip
 driver which may occur when the station attempts a connection
 negotiation during the handling of the remote devices country settings
 leading to denial of service (bsc#1157158).

CVE-2019-18660: Fixed a potential information leak on powerpc because
 the Spectre-RSB mitigation was not in place for all applicable CPUs, aka
 CID-39e72bf96f58 (bsc#1157038).

CVE-2019-18683: Fixed a privilege escalation due to multiple race
 conditions (bsc#1155897).

CVE-2019-18809: Fixed a memory leak in the af9005_identify_state()
 function in drivers/media/usb/dvb-usb/af9005.c aka CID-2289adbfa559
 (bsc#1156258).

CVE-2019-19062: Fixed a memory leak in the crypto_report() function in
 crypto/crypto_user_base.c aka CID-ffdde5932042 (bsc#1157333).

CVE-2019-19057: Fixed two memory leaks in the
 mwifiex_pcie_init_evt_ring() function in
 drivers/net/wireless/marvell/mwifiex/pcie.c aka CID-d10dcb615c8e
 (bsc#1157193).

CVE-2019-19056: Fixed a memory leak in the
 mwifiex_pcie_alloc_cmdrsp_buf() function in
 drivers/net/wireless/marvell/mwifiex/pcie.c aka CID-db8fd2cde932
 (bsc#1157197).

CVE-2019-19068: Fixed a memory leak in the rtl8xxxu_submit_int_urb()
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.47.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.47.1", rls:"SLES15.0"))) {
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
