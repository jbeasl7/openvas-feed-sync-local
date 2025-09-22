# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4505.1");
  script_cve_id("CVE-2022-28693", "CVE-2022-3567", "CVE-2022-3628", "CVE-2022-3635", "CVE-2022-3643", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-19 04:19:33 +0000 (Mon, 19 Dec 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:19 +0000 (Mon, 28 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4505-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224505-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206213");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013250.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).
- CVE-2022-42328: Guests could trigger denial of service via the netback driver (bnc#1206114).
- CVE-2022-42329: Guests could trigger denial of service via the netback driver (bnc#1206113).
- CVE-2022-3643: Guests could trigger NIC interface reset/abort/crash via netback driver (bnc#1206113).
- CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file drivers/atm/idt77252.c (bsc#1204631).
- CVE-2022-41850: Fixed a race condition in roccat_report_event() in drivers/hid/hid-roccat.c (bsc#1203960).
- CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).
- CVE-2022-3628: Fixed potential buffer overflow in brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).
- CVE-2022-3567: Fixed a to race condition in inet6_stream_ops()/inet6_dgram_ops() (bsc#1204414).
- CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in drivers/net/slip (bsc#1205671).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).
- CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver USB driver (bsc#1205220).
- CVE-2022-42895: Fixed an information leak in the net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to leak kernel pointers remotely (bsc#1205705).
- CVE-2022-42896: Fixed a use-after-free vulnerability in the net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req() which may have allowed code execution and leaking kernel memory (respectively) remotely via Bluetooth (bsc#1205709).

The following non-security bugs were fixed:

- Drivers: hv: vmbus: Add VMbus IMC device to unsupported list (git-fixes).
- Drivers: hv: vmbus: Add vmbus_requestor data structure for VMBus hardening (bsc#1204017, bsc#1205617).
- Drivers: hv: vmbus: Drop error message when 'No request id available' (bsc#1204017).
- Drivers: hv: vmbus: Fix handling of messages with transaction ID of zero (bsc#1204017).
- Drivers: hv: vmbus: Fix potential crash on module unload (git-fixes).
- Drivers: hv: vmbus: Introduce vmbus_request_addr_match() (bsc#1204017, bsc#1205617).
- Drivers: hv: vmbus: Introduce vmbus_sendpacket_getid() (bsc#1204017, bsc#1205617).
- Drivers: hv: vmbus: Introduce {lock,unlock}_requestor() (bsc#1204017, bsc#1205617).
- Drivers: hv: vmbus: Move __vmbus_open() (bsc#1204017).
- Drivers: hv: vmbus: Prevent load re-ordering when reading ring buffer (git-fixes).
- Drivers: hv: vmbus: fix double free in the error path of vmbus_add_channel_work() (git-fixes).
- Drivers: hv: vmbus: fix possible memory leak in vmbus_device_register() (git-fixes).
- FDDI: defxx: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.120.1", rls:"SLES12.0SP5"))) {
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
