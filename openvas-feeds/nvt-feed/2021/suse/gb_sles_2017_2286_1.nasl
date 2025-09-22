# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2286.1");
  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-10810", "CVE-2017-11473", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-8831");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 16:51:58 +0000 (Mon, 31 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2286-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172286-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998664");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003165.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.82 to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2017-1000111: Fixed a race condition in net-packet code that could be exploited to cause out-of-bounds memory access (bsc#1052365).
- CVE-2017-1000112: Fixed a race condition in net-packet code that could have been exploited by unprivileged users to gain root access. (bsc#1052311).
- CVE-2017-8831: The saa7164_bus_get function in drivers/media/pci/saa7164/saa7164-bus.c in the Linux kernel allowed local users to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact by changing a certain sequence-number value, aka a 'double fetch' vulnerability (bnc#1037994).
- CVE-2017-7542: The ip6_find_1stfragopt function in net/ipv6/output_core.c in the Linux kernel allowed local users to cause a denial of service (integer overflow and infinite loop) by leveraging the ability to open a raw socket (bnc#1049882).
- CVE-2017-11473: Buffer overflow in the mp_override_legacy_irq() function in arch/x86/kernel/acpi/boot.c in the Linux kernel allowed local users to gain privileges via a crafted ACPI table (bnc#1049603).
- CVE-2017-7533: Race condition in the fsnotify implementation in the Linux kernel allowed local users to gain privileges or cause a denial of service (memory corruption) via a crafted application that leverages simultaneous execution of the inotify_handle_event and vfs_rename functions (bnc#1049483 bnc#1050677).
- CVE-2017-7541: The brcmf_cfg80211_mgmt_tx function in drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux kernel allowed local users to cause a denial of service (buffer overflow and system crash) or possibly gain privileges via a crafted NL80211_CMD_FRAME Netlink packet (bnc#1049645).
- CVE-2017-10810: Memory leak in the virtio_gpu_object_create function in drivers/gpu/drm/virtio/virtgpu_object.c in the Linux kernel allowed attackers to cause a denial of service (memory consumption) by triggering object-initialization failures (bnc#1047277).

The following non-security bugs were fixed:

- acpi/nfit: Add support of NVDIMM memory error notification in ACPI 6.2 (bsc#1052325).
- acpi/nfit: Issue Start ARS to retrieve existing records (bsc#1052325).
- acpi / processor: Avoid reserving IO regions too early (bsc#1051478).
- acpi / scan: Prefer devices without _HID for _ADR matching (git-fixes).
- Add 'shutdown' to 'struct class' (bsc#1053117).
- af_key: Add lock to key dump (bsc#1047653).
- af_key: Fix slab-out-of-bounds in pfkey_compile_policy (bsc#1047354).
- alsa: fm801: Initialize chip after IRQ handler is registered (bsc#1031717).
- alsa: hda - add more ML register definitions (bsc#1048356).
- alsa: hda - add sanity check to force the separate stream tags (bsc#1048356).
- alsa: hda: Add support for parsing new HDA capabilities (bsc#1048356).
- alsa: hdac: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.82~6.3.1", rls:"SLES12.0SP3"))) {
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
