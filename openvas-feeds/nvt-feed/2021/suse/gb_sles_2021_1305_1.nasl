# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1305.1");
  script_cve_id("CVE-2020-11947", "CVE-2020-12829", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13765", "CVE-2020-14364", "CVE-2020-15469", "CVE-2020-15863", "CVE-2020-16092", "CVE-2020-25084", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27617", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20181", "CVE-2021-20203", "CVE-2021-20257", "CVE-2021-3416");
  script_tag(name:"creation_date", value:"2021-04-26 00:00:00 +0000 (Mon, 26 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 17:05:12 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1305-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211305-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182968");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-April/008671.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2021:1305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

- Fix OOB access in sm501 device emulation (CVE-2020-12829, bsc#1172385)
- Fix OOB access possibility in MegaRAID SAS 8708EM2 emulation (CVE-2020-13362 bsc#1172383)
- Fix use-after-free in usb xhci packet handling (CVE-2020-25723, bsc#1178934)
- Fix use-after-free in usb ehci packet handling (CVE-2020-25084, bsc#1176673)
- Fix OOB access in usb hcd-ohci emulation (CVE-2020-25624, bsc#1176682)
- Fix infinite loop (DoS) in usb hcd-ohci emulation (CVE-2020-25625, bsc#1176684)
- Fix guest triggerable assert in shared network handling code (CVE-2020-27617, bsc#1178174)
- Fix OOB access in atapi emulation (CVE-2020-29443, bsc#1181108)
- Fix null pointer deref. (DoS) in mmio ops (CVE-2020-15469, bsc#1173612)
- Fix infinite loop (DoS) in e1000 device emulation (CVE-2021-20257, bsc#1182577)
- Fix OOB access (stack overflow) in rtl8139 NIC emulation (CVE-2021-3416, bsc#1182968)
- Fix OOB access (stack overflow) in other NIC emulations (CVE-2021-3416)
- Fix OOB access in SLIRP ARP packet processing (CVE-2020-29130, bsc#1179467)
- Fix null pointer dereference possibility (DoS) in MegaRAID SAS 8708EM2 emulation (CVE-2020-13659 bsc#1172386
- Fix OOB access in iscsi (CVE-2020-11947 bsc#1180523)
- Fix OOB access in vmxnet3 emulation (CVE-2021-20203 bsc#1181639)
- Fix buffer overflow in the XGMAC device (CVE-2020-15863 bsc#1174386)
- Fix DoS in packet processing of various emulated NICs (CVE-2020-16092 bsc#1174641)
- Fix OOB access while processing USB packets (CVE-2020-14364 bsc#1175441)
- Fix package scripts to not use hard coded paths for temporary working directories and log files (bsc#1182425)
- Fix potential privilege escalation in virtfs (CVE-2021-20181 bsc#1182137)
- Fix OOB access possibility in ES1370 audio device emulation (CVE-2020-13361 bsc#1172384)
- Fix OOB access in ROM loading (CVE-2020-13765 bsc#1172478)");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1_0_gb3ef39f~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1_0_gb3ef39f~41.62.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~41.62.1", rls:"SLES12.0SP2"))) {
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
