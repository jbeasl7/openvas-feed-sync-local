# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123749");
  script_cve_id("CVE-2012-2693");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0127");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0127.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2013-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.8.2-29.0.1.el5]
- Replaced docs/et.png in tarball
- remove virshtest from test cases to fix failure in mock build root

[libvirt-0.8.2-29.el5]
- Coverity pointed out an use after free in the fix for 816601 (rhbz#772848)

[libvirt-0.8.2-28.el5]
- qemu: Rollback on used USB devices (rhbz#816601)
- qemu: Don't delete USB device on failed qemuPrepareHostdevUSBDevices (rhbz#816601)

[libvirt-0.8.2-27.el5]
- qemu: Delete USB devices used by domain on stop (rhbz#816601)

[libvirt-0.8.2-26.el5]
- Fix off-by-1 in virFileAbsPath. (rhbz#680289)
- Fix autostart flag when loading running domains (rhbz#675319)
- node_device: Avoid null dereference on error (rhbz#772848)
- util: Avoid null deref on qcowXGetBackingStore (rhbz#772848)
- docs: Improve virsh domxml-*-native command docs (rhbz#783001)
- Clarify the purpose of domxml-from-native (rhbz#783001)
- qemu: Add return value check (rhbz#772821)
- storage: Avoid mishandling backing store > 2GB (rhbz#772821)
- util: Avoid PATH_MAX-sized array (rhbz#816601)
- qemu: Keep list of USB devices attached to domains (rhbz#816601)
- qemu: Don't leak temporary list of USB devices (rhbz#816601)
- usb: Create functions to search usb device accurately (rhbz#816601)
- qemu: Call usb search function for hostdev initialization and hotplug (rhbz#816601)
- usb: Fix crash when failing to attach a second usb device (rhbz#816601)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~29.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~29.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~29.0.1.el5", rls:"OracleLinux5"))) {
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
