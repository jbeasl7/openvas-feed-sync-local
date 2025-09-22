# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891497");
  script_cve_id("CVE-2015-8666", "CVE-2016-10155", "CVE-2016-2198", "CVE-2016-6833", "CVE-2016-6835", "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-9602", "CVE-2016-9603", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9914", "CVE-2016-9915", "CVE-2016-9916", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11434", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-18030", "CVE-2017-18043", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5579", "CVE-2017-5667", "CVE-2017-5715", "CVE-2017-5856", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9503", "CVE-2018-5683", "CVE-2018-7550");
  script_tag(name:"creation_date", value:"2018-09-06 22:00:00 +0000 (Thu, 06 Sep 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:42:19 +0000 (Thu, 10 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-1497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1497-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1497-1");
  script_xref(name:"URL", value:"https://www.qemu.org/2018/01/04/spectre/");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-1497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in qemu, a fast processor emulator:

CVE-2015-8666

Heap-based buffer overflow in QEMU when built with the Q35-chipset-based PC system emulator

CVE-2016-2198

Null pointer dereference in ehci_caps_write in the USB EHCI support that may result in denial of service

CVE-2016-6833

Use after free while writing in the vmxnet3 device that could be used to cause a denial of service

CVE-2016-6835

Buffer overflow in vmxnet_tx_pkt_parse_headers() in vmxnet3 device that could result in denial of service

CVE-2016-8576

Infinite loop vulnerability in xhci_ring_fetch in the USB xHCI support

CVE-2016-8667 / CVE-2016-8669 Divide by zero errors in set_next_tick in the JAZZ RC4030 chipset emulator, and in serial_update_parameters of some serial devices, that could result in denial of service

CVE-2016-9602

Improper link following with VirtFS

CVE-2016-9603

Heap buffer overflow via vnc connection in the Cirrus CLGD 54xx VGA emulator support

CVE-2016-9776

Infinite loop while receiving data in the ColdFire Fast Ethernet Controller emulator

CVE-2016-9907

Memory leakage in the USB redirector usb-guest support

CVE-2016-9911

Memory leakage in ehci_init_transfer in the USB EHCI support

CVE-2016-9914 / CVE-2016-9915 / CVE-2016-9916 Plan 9 File System (9pfs): add missing cleanup operation in FileOperations, in the handle backend and in the proxy backend driver

CVE-2016-9921 / CVE-2016-9922 Divide by zero in cirrus_do_copy in the Cirrus CLGD 54xx VGA Emulator support

CVE-2016-10155

Memory leak in hw/watchdog/wdt_i6300esb.c allowing local guest OS privileged users to cause a denial of service via a large number of device unplug operations.

CVE-2017-2615 / CVE-2017-2620 / CVE-2017-18030 / CVE-2018-5683 / CVE-2017-7718 Out-of-bounds access issues in the Cirrus CLGD 54xx VGA emulator support, that could result in denial of service

CVE-2017-5525 / CVE-2017-5526 Memory leakage issues in the ac97 and es1370 device emulation

CVE-2017-5579

Most memory leakage in the 16550A UART emulation

CVE-2017-5667

Out-of-bounds access during multi block SDMA transfer in the SDHCI emulation support.

CVE-2017-5715

Mitigations against the Spectre v2 vulnerability. For more information please refer to [link moved to references]

CVE-2017-5856

Memory leak in the MegaRAID SAS 8708EM2 Host Bus Adapter emulation support

CVE-2017-5973 / CVE-2017-5987 / CVE-2017-6505 Infinite loop issues in the USB xHCI, in the transfer mode register of the SDHCI protocol, and the USB ohci_service_ed_list

CVE-2017-7377

9pfs: host memory leakage via v9fs_create

CVE-2017-7493

Improper access control issues in the host directory sharing via 9pfs support.

CVE-2017-7980

Heap-based buffer overflow in the Cirrus VGA device that could allow local guest OS users to execute arbitrary code or cause a denial of service

CVE-2017-8086

9pfs: host memory leakage via ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8"))) {
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
