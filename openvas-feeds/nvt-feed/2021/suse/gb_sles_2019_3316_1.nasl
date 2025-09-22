# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3316.1");
  script_cve_id("CVE-2019-0154", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19543");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 14:55:37 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3316-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3316-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193316-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159024");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006267.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3316-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel-azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-19051: There was a memory leak in the i2400m_op_rfkill_sw_toggle() function in drivers/net/wimax/i2400m/op-rfkill.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) (bnc#1159024).
- CVE-2019-19338: There was an incomplete fix for Transaction Asynchronous Abort (TAA) (bnc#1158954).
- CVE-2019-19332: There was an OOB memory write via kvm_dev_ioctl_get_cpuid (bnc#1158827).
- CVE-2019-19537: There was a race condition bug that can be caused by a malicious USB device in the USB character device driver layer (bnc#1158904).
- CVE-2019-19535: There was an info-leak bug that can be caused by a malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_fd.c driver (bnc#1158903).
- CVE-2019-19527: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/hid/usbhid/hiddev.c driver (bnc#1158900).
- CVE-2019-19526: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/nfc/pn533/usb.c driver (bnc#1158893).
- CVE-2019-19533: There was an info-leak bug that can be caused by a malicious USB device in the drivers/media/usb/ttusb-dec/ttusb_dec.c driver (bnc#1158834).
- CVE-2019-19532: There were multiple out-of-bounds write bugs that can be caused by a malicious USB device in the Linux kernel HID drivers (bnc#1158824).
- CVE-2019-19523: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79 (bnc#1158381 1158823 1158834).
- CVE-2019-15213: There was a use-after-free caused by a malicious USB device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver (bnc#1146544).
- CVE-2019-19531: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/misc/yurex.c driver (bnc#1158445).
- CVE-2019-19543: There was a use-after-free in serial_ir_init_module() in drivers/media/rc/serial_ir.c (bnc#1158427).
- CVE-2019-19525: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/net/ieee802154/atusb.c driver (bnc#1158417).
- CVE-2019-19530: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/class/cdc-acm.c driver (bnc#1158410).
- CVE-2019-19536: There was an info-leak bug that can be caused by a malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_pro.c driver (bnc#1158394).
- CVE-2019-19524: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/input/ff-memless.c driver (bnc#1158413).
- CVE-2019-19528: There was a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/misc/iowarrior.c driver (bnc#1158407).
- CVE-2019-19534: There was an info-leak bug that can be ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.34.1", rls:"SLES12.0SP4"))) {
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
