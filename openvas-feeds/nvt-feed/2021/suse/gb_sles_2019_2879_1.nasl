# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2879.1");
  script_cve_id("CVE-2017-18595", "CVE-2019-14821", "CVE-2019-15291", "CVE-2019-16232", "CVE-2019-16234", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-21 18:30:04 +0000 (Mon, 21 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2879-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192879-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154747");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-October/006082.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2017-18595: A double free may be caused by the function allocate_trace_buffer in the file kernel/trace/trace.c (bnc#1149555).
- CVE-2019-14821: An out-of-bounds access issue was found in the way Linux kernel's KVM hypervisor implements the coalesced MMIO write operation. It operates on an MMIO ring buffer 'struct kvm_coalesced_mmio' object, wherein write indices 'ring->first' and 'ring->last' value could be supplied by a host user-space process. An unprivileged host user or process with access to '/dev/kvm' device could use this flaw to crash the host kernel, resulting in a denial of service or potentially escalating privileges on the system (bnc#1151350).
- CVE-2019-15291: There was a NULL pointer dereference caused by a malicious USB device in the flexcop_usb_probe function in the drivers/media/usb/b2c2/flexcop-usb.c driver (bnc#1146540).
- CVE-2019-9506: The Bluetooth BR/EDR specification up to and including version 5.1 permitted sufficiently low encryption key length and did not prevent an attacker from influencing the key length negotiation. This allowed practical brute-force attacks (aka 'KNOB') that could decrypt traffic and injected arbitrary ciphertext without the victim noticing (bnc#1137865 bnc#1146042).
- CVE-2019-16232: Fixed a NULL pointer dereference in drivers/net/wireless/marvell/libertas/if_sdio.c, which did not check the alloc_workqueue return value (bnc#1150465).
- CVE-2019-16234: Fixed a NULL pointer dereference in drivers/net/wireless/intel/iwlwifi/pcie/trans.c, which did not check the alloc_workqueue return value (bnc#1150452).
- CVE-2019-17056: Added enforcement of CAP_NET_RAW in llcp_sock_create in net/nfc/llcp_sock.c in the AF_NFC network module, the lack of which allowed unprivileged users to create a raw socket, aka CID-3a359798b176 (bnc#1152788).
- CVE-2019-17133: Fixed a buffer overflow in cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c caused by long SSID IEs (bsc#1153158).
- CVE-2019-17666: Added an upper-bound check in rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c, the lack of which could have led to a buffer overflow (bnc#1154372).

The following non-security bugs were fixed:

- 9p: avoid attaching writeback_fid on mmap with type PRIVATE (bsc#1051510).
- ACPI / CPPC: do not require the _PSD method (bsc#1051510).
- ACPI: CPPC: Set pcc_data[pcc_ss_id] to NULL in acpi_cppc_processor_exit() (bsc#1051510).
- ACPI: custom_method: fix memory leaks (bsc#1051510).
- ACPI / PCI: fix acpi_pci_irq_enable() memory leak (bsc#1051510).
- ACPI / processor: do not print errors for processorIDs == 0xff (bsc#1051510).
- ACPI / property: Fix acpi_graph_get_remote_endpoint() name in kerneldoc (bsc#1051510).
- act_mirred: Fix mirred_init_module error handling (bsc#1051510).
- Add kernel module ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.37.1", rls:"SLES12.0SP4"))) {
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
