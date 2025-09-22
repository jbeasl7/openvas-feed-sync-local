# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130069");
  script_cve_id("CVE-2015-3209", "CVE-2015-3214", "CVE-2015-4037", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-5154", "CVE-2015-5745");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:20 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 21:03:28 +0000 (Tue, 28 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0310");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0310.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/08/06/5");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2630-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16105");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-1507.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2015-0310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Tait discovered that QEMU incorrectly handled the virtual PCNET
driver. A malicious guest could use this issue to cause a denial of
service, or possibly execute arbitrary code on the host as the user
running the QEMU process (CVE-2015-3209).

Kurt Seifried discovered that QEMU incorrectly handled certain temporary
files. A local attacker could use this issue to cause a denial of service
(CVE-2015-4037).

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the host MSI message data field. A malicious guest could use
this issue to cause a denial of service (CVE-2015-4103).

Jan Beulich discovered that the QEMU Xen code incorrectly restricted
access to the PCI MSI mask bits. A malicious guest could use this issue to
cause a denial of service (CVE-2015-4104).

Jan Beulich discovered that the QEMU Xen code incorrectly handled MSI-X
error messages. A malicious guest could use this issue to cause a denial
of service (CVE-2015-4105).

Jan Beulich discovered that the QEMU Xen code incorrectly restricted write
access to the PCI config space. A malicious guest could use this issue to
cause a denial of service, obtain sensitive information, or possibly
execute arbitrary code (CVE-2015-4106).

A heap buffer overflow flaw was found in the way QEMU's IDE subsystem
handled I/O buffer access while processing certain ATAPI commands.
A privileged guest user in a guest with the CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with the
privileges of the host's QEMU process corresponding to the guest
(CVE-2015-5154).

An out-of-bounds memory access flaw, leading to memory corruption or
possibly an information leak, was found in QEMU's pit_ioport_read()
function. A privileged guest user in a QEMU guest, which had QEMU PIT
emulation enabled, could potentially, in rare cases, use this flaw to
execute arbitrary code on the host with the privileges of the hosting QEMU
process (CVE-2015-3214).

Qemu emulator built with the virtio-serial vmchannel support is vulnerable
to a buffer overflow issue. It could occur while exchanging virtio control
messages between guest & the host. A malicious guest could use this flaw
to corrupt few bytes of Qemu memory area, potentially crashing the Qemu
process (CVE-2015-5745).");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.6.2~1.12.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.6.2~1.12.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.1.3~2.3.mga5", rls:"MAGEIA5"))) {
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
