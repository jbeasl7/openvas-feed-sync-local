# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131187");
  script_cve_id("CVE-2015-7504", "CVE-2015-7512", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8666", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1714");
  script_tag(name:"creation_date", value:"2016-01-18 05:49:19 +0000 (Mon, 18 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-08 17:04:31 +0000 (Fri, 08 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0023");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0023.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17260");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2016-0023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow flaw was discovered in the way QEMU's AMD
PC-Net II Ethernet Controller emulation received certain packets in
loopback mode. A privileged user (with the CAP_SYS_RAWIO capability)
inside a guest could use this flaw to crash the host QEMU process
(resulting in denial of service) or, potentially, execute arbitrary code
with privileges of the host QEMU process (CVE-2015-7504)

A buffer overflow flaw was found in the way QEMU's AMD PC-Net II emulation
validated certain received packets from a remote host in non-loopback mode.
A remote, unprivileged attacker could potentially use this flaw to execute
arbitrary code on the host with the privileges of the QEMU process. Note
that to exploit this flaw, the guest network interface must have a large
MTU limit (CVE-2015-7512)

A NULL pointer dereference vulnerability was found in the QEMU emulator
built with PCI MSI-X support. Because MSI-X MMIO support did not define
the .write method, when the controller tried to write to the pending bit
array(PBA) memory region, a segmentation fault occurred. A privileged
attacker inside the guest could use this flaw to crash the QEMU process
resulting in denial of service (CVE-2015-7549)

An infinite-loop flaw was discovered in the QEMU emulator built with i8255x
(PRO100) emulation support. When processing a chain of commands located in
the Command Block List(CBL), each Command Block(CB) points to the next
command in the list. If the link to the next CB pointed to the same block
or if there was a closed loop in the chain, an infinite loop would execute
the same command over and over again. A privileged user inside the guest
could use this flaw to crash the QEMU instance, resulting in denial of
service (CVE-2015-8345).

An arithmetic-exception flaw was found in the QEMU emulator built with VNC
display-driver support. The VNC server incorrectly handled 'SetPixelFormat'
messages sent from clients. A privileged remote client could use this flaw
to crash the guest resulting in denial of service (CVE-2015-8504).

An infinite-loop issue was found in the QEMU emulator built with USB EHCI
emulation support. The flaw occurred during communication between the host
controller interface(EHCI) and a respective device driver. These two
communicate using an isochronous transfer descriptor list(iTD). an infinite
loop unfolded if there was a closed loop in the list. A privileged user
inside a guest could use this flaw to consume excessive resources and cause
denial of service (CVE-2015-8558).

A memory-leak flaw was found in the QEMU emulator built with VMWARE VMXNET3
paravirtual NIC emulator support. The flaw occurred when a guest repeatedly
tried to activate the VMXNET3 device. A privileged guest attacker could use
this flaw to leak host memory, resulting in denial of service on the host.
(CVE-2015-8567, CVE-2015-8568)

A stack buffer-overflow vulnerability has been discovered in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.11.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.1.3~2.11.mga5", rls:"MAGEIA5"))) {
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
