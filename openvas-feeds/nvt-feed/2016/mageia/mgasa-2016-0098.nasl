# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131256");
  script_cve_id("CVE-2015-0268", "CVE-2015-1563", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2150", "CVE-2015-2151", "CVE-2015-2152", "CVE-2015-2751", "CVE-2015-2752", "CVE-2015-2756", "CVE-2015-3209", "CVE-2015-3259", "CVE-2015-3340", "CVE-2015-3456", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-5154", "CVE-2015-5165", "CVE-2015-5166", "CVE-2015-5307", "CVE-2015-6654", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7812", "CVE-2015-7813", "CVE-2015-7814", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8338", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8550", "CVE-2015-8555", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-2270", "CVE-2016-2271");
  script_tag(name:"creation_date", value:"2016-03-08 05:15:19 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 14:39:31 +0000 (Tue, 24 Oct 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0098");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0098.html");
  script_xref(name:"URL", value:"http://www.xenproject.org/downloads/xen-archives/xen-45-series/xen-451.html");
  script_xref(name:"URL", value:"http://www.xenproject.org/downloads/xen-archives/xen-45-series/xen-452.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-117.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-118.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-119.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-120.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-121.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-122.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-123.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-124.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-125.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-126.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-127.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-128.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-129.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-130.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-131.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-132.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-133.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-134.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-135.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-136.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-137.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-138.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-139.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-140.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-141.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-142.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-145.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-146.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-147.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-148.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-149.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-150.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-151.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-152.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-153.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-154.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-155.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-156.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-158.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-159.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-162.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-163.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-164.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-165.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-166.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-167.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-168.html");
  script_xref(name:"URL", value:"http://xenbits.xen.org/xsa/advisory-170.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16956");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the MGASA-2016-0098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This xen update is based on upstream 4.5.2 maintenance release, and fixes the
following security issues:

The vgic_v2_to_sgi function in arch/arm/vgic-v2.c in Xen 4.5.x, when running
on ARM hardware with general interrupt controller (GIC) version 2, allows
local guest users to cause a denial of service (host crash) by writing an
invalid value to the GICD.SGIR register (CVE-2015-0268).

The ARM GIC distributor virtualization in Xen 4.4.x and 4.5.x allows local
guests to cause a denial of service by causing a large number messages to
be logged (CVE-2015-1563).

The emulation routines for unspecified X86 devices in Xen 3.2.x through
4.5.x does not properly initialize data, which allow local HVM guest users
to obtain sensitive information via vectors involving an unsupported access
size (CVE-2015-2044).

The HYPERVISOR_xen_version hypercall in Xen 3.2.x through 4.5.x does not
properly initialize data structures, which allows local guest users to
obtain sensitive information via unspecified vectors (CVE-2015-2045).

Xen 3.3.x through 4.5.x and the Linux kernel through 3.19.1 do not properly
restrict access to PCI command registers, which might allow local guest
users to cause a denial of service (non-maskable interrupt and host crash)
by disabling the (1) memory or (2) I/O decoding for a PCI Express device
and then accessing the device, which triggers an Unsupported Request (UR)
response (CVE-2015-2150).

The x86 emulator in Xen 3.2.x through 4.5.x does not properly ignore segment
overrides for instructions with register operands, which allows local guest
users to obtain sensitive information, cause a denial of service (memory
corruption), or possibly execute arbitrary code via unspecified vectors
(CVE-2015-2151).

Xen 4.5.x and earlier enables certain default backends when emulating a VGA
device for an x86 HVM guest qemu even when the configuration disables them,
which allows local guest users to obtain access to the VGA console by (1)
setting the DISPLAY environment variable, when compiled with SDL support,
or connecting to the VNC server on (2) ::1 or (3) 127.0.0.1, when not
compiled with SDL support (CVE-2015-2152).

Xen 4.3.x, 4.4.x, and 4.5.x, when using toolstack disaggregation, allows
remote domains with partial management control to cause a denial of service
(host lock) via unspecified domctl operations (CVE-2015-2751).

The XEN_DOMCTL_memory_mapping hypercall in Xen 3.2.x through 4.5.x, when
using a PCI passthrough device, is not preemptible, which allows local x86
HVM domain users to cause a denial of service (host CPU consumption) via
a crafted request to the device model (qemu-dm) (CVE-2015-2752).

QEMU, as used in Xen 3.3.x through 4.5.x, does not properly restrict access
to PCI command registers, which might allow local HVM guest users to cause
a denial of service (non-maskable interrupt and host crash) by disabling
the (1) memory or (2) I/O decoding for a PCI ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xen-devel", rpm:"lib64xen-devel~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xen3.0", rpm:"lib64xen3.0~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen-devel", rpm:"libxen-devel~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen3.0", rpm:"libxen3.0~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen", rpm:"ocaml-xen~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen-devel", rpm:"ocaml-xen-devel~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc", rpm:"xen-doc~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.5.2~1.5.mga5", rls:"MAGEIA5"))) {
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
