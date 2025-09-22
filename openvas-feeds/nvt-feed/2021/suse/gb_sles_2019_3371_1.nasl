# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3371.1");
  script_cve_id("CVE-2019-14895", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-17055", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-19 14:12:49 +0000 (Tue, 19 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3371-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193371-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156187");
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
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006278.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2019-14895: A heap-based buffer overflow was discovered in the Linux kernel in Marvell WiFi chip driver. The flaw could occur when the station attempts a connection negotiation during the handling of the remote devices country settings. This could have allowed the remote device to cause a denial of service (system crash) or possibly execute arbitrary code (bnc#1157158).
- CVE-2019-18660: The Linux kernel on powerpc allowed Information Exposure because the Spectre-RSB mitigation is not in place for all applicable CPUs. This is related to arch/powerpc/kernel/entry_64.S and arch/powerpc/kernel/security.c (bnc#1157038).
- CVE-2019-18683: An issue was discovered in drivers/media/platform/vivid in the Linux kernel. It is exploitable for privilege escalation on some Linux distributions where local users have /dev/video0 access, but only if the driver happens to be loaded. There are multiple race conditions during streaming stopping in this driver (part of the V4L2 subsystem). These issues are caused by wrong mutex locking in vivid_stop_generating_vid_cap(), vivid_stop_generating_vid_out(), sdr_cap_stop_streaming(), and the corresponding kthreads. At least one of these race conditions leads to a use-after-free (bnc#1155897).
- CVE-2019-18809: A memory leak in the af9005_identify_state() function in drivers/media/usb/dvb-usb/af9005.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) (bnc#1156258).
- CVE-2019-19062: A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) by triggering crypto_report_alg() failures (bnc#1157333).
- CVE-2019-19057: Two memory leaks in the mwifiex_pcie_init_evt_ring() function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures (bnc#1157197).
- CVE-2019-19056: A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf() function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) by triggering mwifiex_map_pci_memory() failures (bnc#1157197).
- CVE-2019-19068: A memory leak in the rtl8xxxu_submit_int_urb() function in drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) by triggering usb_submit_urb() failures (bnc#1157307).
- CVE-2019-19063: Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) (bnc#1157298).
- CVE-2019-19227: In the AppleTalk subsystem ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.45.1", rls:"SLES12.0SP4"))) {
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
