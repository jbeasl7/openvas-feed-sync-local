# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891599");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-6351", "CVE-2016-6834", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7421", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2017-10664", "CVE-2018-10839", "CVE-2018-17962", "CVE-2018-17963");
  script_tag(name:"creation_date", value:"2018-12-02 23:00:00 +0000 (Sun, 02 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("Debian: Security Advisory (DLA-1599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1599-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1599-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-1599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in QEMU, a fast processor emulator:

CVE-2016-2391

Zuozhi Fzz discovered that eof_times in USB OHCI emulation support could be used to cause a denial of service, via a null pointer dereference.

CVE-2016-2392 / CVE-2016-2538 Qinghao Tang found a NULL pointer dereference and multiple integer overflows in the USB Net device support that could allow local guest OS administrators to cause a denial of service. These issues related to remote NDIS control message handling.

CVE-2016-2841

Yang Hongke reported an infinite loop vulnerability in the NE2000 NIC emulation support.

CVE-2016-2857

Liu Ling found a flaw in QEMU IP checksum routines. Attackers could take advantage of this issue to cause QEMU to crash.

CVE-2016-2858

Arbitrary stack based allocation in the Pseudo Random Number Generator (PRNG) back-end support.

CVE-2016-4001 / CVE-2016-4002 Oleksandr Bazhaniuk reported buffer overflows in the Stellaris and the MIPSnet ethernet controllers emulation. Remote malicious users could use these issues to cause QEMU to crash.

CVE-2016-4020

Donghai Zdh reported that QEMU incorrectly handled the access to the Task Priority Register (TPR), allowing local guest OS administrators to obtain sensitive information from host stack memory.

CVE-2016-4037

Du Shaobo found an infinite loop vulnerability in the USB EHCI emulation support.

CVE-2016-4439 / CVE-2016-4441 / CVE-2016-5238 / CVE-2016-5338 / CVE-2016-6351 Li Qiang found different issues in the QEMU 53C9X Fast SCSI Controller (FSC) emulation support, that made it possible for local guest OS privileged users to cause denials of service or potentially execute arbitrary code.

CVE-2016-4453 / CVE-2016-4454 Li Qiang reported issues in the QEMU VMWare VGA module handling, that may be used to cause QEMU to crash, or to obtain host sensitive information.

CVE-2016-4952 / CVE-2016-7421 / CVE-2016-7156 Li Qiang reported flaws in the VMware paravirtual SCSI bus emulation support. These issues concern an out-of-bounds access and infinite loops, that allowed local guest OS privileged users to cause a denial of service.

CVE-2016-5105 / CVE-2016-5106 / CVE-2016-5107 / CVE-2016-5337 Li Qiang discovered several issues in the MegaRAID SAS 8708EM2 Host Bus Adapter emulation support. These issues include stack information leakage while reading configuration and out-of-bounds write and read.

CVE-2016-6834

Li Qiang reported an infinite loop vulnerability during packet fragmentation in the network transport abstraction layer support. Local guest OS privileged users could made use of this flaw to cause a denial of service.

CVE-2016-6836 / CVE-2016-6888 Li Qiang found issues in the VMWare VMXNET3 network card emulation support, relating to information leak and integer overflow in packet initialisation.

CVE-2016-7116

Felix Wilhel discovered a directory traversal flaw in the Plan 9 File System (9pfs), ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8"))) {
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
