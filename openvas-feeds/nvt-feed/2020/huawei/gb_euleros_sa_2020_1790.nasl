# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1790");
  script_cve_id("CVE-2016-4952", "CVE-2016-7907", "CVE-2017-10806", "CVE-2017-11434", "CVE-2017-13711", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5856", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-7493", "CVE-2017-8112", "CVE-2017-8380", "CVE-2017-9524", "CVE-2018-11806", "CVE-2018-15746", "CVE-2018-16872", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849", "CVE-2018-19364", "CVE-2018-19489", "CVE-2018-19665", "CVE-2018-20815", "CVE-2019-11135", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-20175", "CVE-2019-3812", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2020-07-03 06:26:07 +0000 (Fri, 03 Jul 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 15:41:33 +0000 (Mon, 03 Jun 2019)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-1790)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1790");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1790");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2020-1790 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak in hw/audio/es1370.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption and QEMU process crash) via a large number of device unplug operations.(CVE-2017-5526)

Memory leak in hw/audio/ac97.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption and QEMU process crash) via a large number of device unplug operations.(CVE-2017-5525)

The xhci_kick_epctx function in hw/usb/hcd-xhci.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (infinite loop and QEMU process crash) via vectors related to control transfer descriptor sequence.(CVE-2017-5973)

The sdhci_sdma_transfer_multi_blocks function in hw/sd/sdhci.c in QEMU (aka Quick Emulator) allows local OS guest privileged users to cause a denial of service (infinite loop and QEMU process crash) via vectors involving the transfer mode register during multi block transfer.(CVE-2017-5987)

Memory leak in the megasas_handle_dcmd function in hw/scsi/megasas.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption) via MegaRAID Firmware Interface (MFI) commands with the sglist size set to a value over 2 Gb.(CVE-2017-5856)

qemu_deliver_packet_iov in net/net.c in Qemu accepts packet sizes greater than INT_MAX, which allows attackers to cause a denial of service or possibly have unspecified other impact.(CVE-2018-17963)

qemu-bridge-helper.c in QEMU 4.0.0 does not ensure that a network interface name (obtained from bridge.conf or a --br=bridge option) is limited to the IFNAMSIZ size, which can lead to an ACL bypass.(CVE-2019-13164)

Buffer overflow in the 'megasas_mmio_write' function in Qemu 2.9.0 allows remote attackers to have unspecified impact via unknown vectors.(CVE-2017-8380)

Quick Emulator (Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an improper access control issue. It could occur while accessing virtfs metadata files in mapped-file security mode. A guest user could use this flaw to escalate their privileges inside guest.(CVE-2017-7493)

In QEMU 3.1.0, load_device_tree in device_tree.c calls the deprecated load_image function, which has a buffer overflow risk.(CVE-2018-20815)

Use-after-free vulnerability in the sofree function in slirp/socket.c in QEMU (aka Quick Emulator) allows attackers to cause a denial of service (QEMU instance crash) by leveraging failure to properly clear ifq_so from pending packets.(CVE-2017-13711)

Stack-based buffer overflow in hw/usb/redirect.c in QEMU (aka Quick Emulator) allows local guest OS users to cause a denial of service (QEMU process crash) via vectors related to logging debug messages.(CVE-2017-10806)

The dhcp_decode function in slirp/bootp.c in QEMU (aka Quick ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~2.8.1~30.184", rls:"EULEROSVIRT-3.0.6.0"))) {
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
