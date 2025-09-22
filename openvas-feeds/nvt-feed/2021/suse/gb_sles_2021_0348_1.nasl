# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0348.1");
  script_cve_id("CVE-2020-25639", "CVE-2020-27835", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-36158", "CVE-2021-0342", "CVE-2021-20177", "CVE-2021-3347");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:02:01 +0000 (Thu, 04 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0348-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210348-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901327");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-February/008288.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2021-3347: A use-after-free was discovered in the PI futexes during fault handling, allowing local users to execute code in the kernel (bnc#1181349).
- CVE-2021-20177: Fixed a kernel panic related to iptables string matching rules. A privileged user could insert a rule which could lead to denial of service (bnc#1180765).
- CVE-2021-0342: In tun_get_user of tun.c, there is possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges required. (bnc#1180812)
- CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was found, specifically in the way user calls Ioctl after open dev file and fork. A local user could use this flaw to crash the system (bnc#1179878).
- CVE-2020-25639: Fixed a NULL pointer dereference via nouveau ioctl (bnc#1176846).
- CVE-2020-29569: Fixed a potential privilege escalation and information leaks related to the PV block backend, as used by Xen (bnc#1179509).
- CVE-2020-29568: Fixed a denial of service issue, related to processing watch events (bnc#1179508).
- CVE-2020-36158: Fixed an issue wich might have allowed a remote attacker to execute arbitrary code via a long SSID value in mwifiex_cmd_802_11_ad_hoc_start() (bnc#1180559).
- CVE-2020-28374: Fixed a vulnerability caused by insufficient identifier checking in the LIO SCSI target code. This could have been used by a remote attacker to read or write files via directory traversal in an XCOPY request (bnc#1178372).

The following non-security bugs were fixed:

- ACPICA: Disassembler: create buffer fields in ACPI_PARSE_LOAD_PASS1 (git-fixes).
- ACPICA: Do not increment operation_region reference counts for field units (git-fixes).
- ACPI: PNP: compare the string length in the matching_id() (git-fixes).
- ACPI: scan: add stub acpi_create_platform_device() for !CONFIG_ACPI (git-fixes).
- ACPI: scan: Harden acpi_device_add() against device ID overflows (git-fixes).
- ACPI: scan: Make acpi_bus_get_device() clear return pointer on error (git-fixes).
- ALSA: ca0106: fix error code handling (git-fixes).
- ALSA: ctl: allow TLV read operation for callback type of element in locked case (git-fixes).
- ALSA: doc: Fix reference to mixart.rst (git-fixes).
- ALSA: fireface: Fix integer overflow in transmit_midi_msg() (git-fixes).
- ALSA: firewire-tascam: Fix integer overflow in midi_port_work() (git-fixes).
- ALSA: hda: Add NVIDIA codec IDs 9a & 9d through a0 to patch table (git-fixes).
- ALSA: hda: Fix potential race in unsol event handler (git-fixes).
- ALSA: hda - Fix silent audio output and corrupted input on MSI X570-A PRO (git-fixes).
- ALSA: hda/generic: Add option to enforce preferred_dacs pairs (git-fixes).
- ALSA: hda/hdmi: always check pin power status in i915 pin fixup ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.44.1", rls:"SLES12.0SP5"))) {
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
