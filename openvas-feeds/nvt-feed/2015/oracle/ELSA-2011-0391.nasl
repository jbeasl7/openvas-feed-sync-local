# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122206");
  script_cve_id("CVE-2011-1146");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:47 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0391)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0391");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0391.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2011-0391 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.8.1-27.0.1.el6_0.5]
- Replace docs/et.png in tarball with blank image

[0.8.1-27.el6_0.5]
- Properly report error in virConnectDomainXMLToNative (CVE-2011-1146)

[0.8.1-27.el6_0.4]
- Add missing checks for read-only connections (CVE-2011-1146)

[0.8.1-27.el6_0.3]
- Remove patches not suitable for proper Z-stream:
 - Export host information through SMBIOS to guests (rhbz#652678)
 - Support forcing a CDROM eject (rhbz#658147)
- Plug several memory leaks (rhbz#672549)
- Avoid memory overhead of matchpathcon (rhbz#672554)
- Do not start libvirt-guests if that service is off (rhbz#668694)

[0.8.1-27.el6_0.2]
- spec file cleanups (rhbz#662045)
- Fix deadlock on concurrent multiple bidirectional migration (rhbz#662043)
- Fix off-by-one error in clock-variable (rhbz#662046)
- Export host information through SMBIOS to guests (rhbz#652678)
- Ensure device is deleted from guest after unplug (rhbz#662041)
- Distinguish between QEMU domain shutdown and crash (rhbz#662042)

[0.8.1-27.el6_0.1]
- Fix JSON migrate_set_downtime command (rhbz#658143)
- Make SASL work over UNIX domain sockets (rhbz#658144)
- Let qemu group look below /var/lib/libvirt/qemu/ (rhbz#656972)
- Fix save/restore on root_squashed NFS (rhbz#656355)
- Fix race on multiple migration (rhbz#658141)
- Export host information through SMBIOS to guests (rhbz#652678)
- Support forcing a CDROM eject (rhbz#658147)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~15.0.1.el5_6.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.1~27.0.1.el6_0.5", rls:"OracleLinux6"))) {
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
