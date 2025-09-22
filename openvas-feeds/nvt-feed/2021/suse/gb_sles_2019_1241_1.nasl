# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1241.1");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16880", "CVE-2019-11091", "CVE-2019-3882", "CVE-2019-9003", "CVE-2019-9500", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:12 +0000 (Wed, 29 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1241-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1241-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191241-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133852");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-May/005457.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1241-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

Four new speculative execution information leak issues have been identified in Intel CPUs. (bsc#1111331)

- CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)
- CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)
- CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)
- CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory (MDSUM)

This kernel update contains software mitigations for these issues, which also utilize CPU microcode updates shipped in parallel.


For more information on this set of vulnerabilities, check out [link moved to references]

The following security bugs were fixed:

- CVE-2018-16880: A flaw was found in the handle_rx() function in the vhost_net driver. A malicious virtual guest, under specific conditions, could trigger an out-of-bounds write in a kmalloc-8 slab on a virtual host which may lead to a kernel memory corruption and a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (bnc#1122767).
- CVE-2019-3882: A flaw was found in the vfio interface implementation that permitted violation of the user's locked memory limit. If a device is bound to a vfio driver, such as vfio-pci, and the local attacker is administratively granted ownership of the device, it may cause a system memory exhaustion and thus a denial of service (DoS). (bnc#1131416 bnc#1131427).
- CVE-2019-9003: Attackers could trigger a drivers/char/ipmi/ipmi_msghandler.c use-after-free and OOPS by arranging for certain simultaneous execution of the code, as demonstrated by a 'service ipmievd restart' loop (bnc#1126704).
- CVE-2019-9500: A brcmfmac heap buffer overflow in brcmf_wowl_nd_results was fixed. (bnc#1132681).
- CVE-2019-9503: A brcmfmac frame validation bypass was fixed. (bnc#1132828).

The following non-security bugs were fixed:

- 9p: do not trust pdu content for stat item size (bsc#1051510).
- ACPI: acpi_pad: Do not launch acpi_pad threads on idle cpus (bsc#1113399).
- acpi, nfit: Prefer _DSM over _LSR for namespace label reads (bsc#1112128) (bsc#1132426).
- ACPI / SBS: Fix GPE storm on recent MacBookPro's (bsc#1051510).
- alsa: core: Fix card races between register and disconnect (bsc#1051510).
- alsa: echoaudio: add a check for ioremap_nocache (bsc#1051510).
- alsa: firewire: add const qualifier to identifiers for read-only symbols (bsc#1051510).
- alsa: firewire-motu: add a flag for AES/EBU on XLR interface (bsc#1051510).
- alsa: firewire-motu: add specification flag for position of flag for MIDI messages (bsc#1051510).
- alsa: firewire-motu: add support for MOTU Audio Express (bsc#1051510).
- alsa: firewire-motu: add support for Motu Traveler (bsc#1051510).
- alsa: firewire-motu: use 'version' field of unit directory to identify model (bsc#1051510).
- alsa: hda - add Lenovo ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.16.1", rls:"SLES12.0SP4"))) {
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
