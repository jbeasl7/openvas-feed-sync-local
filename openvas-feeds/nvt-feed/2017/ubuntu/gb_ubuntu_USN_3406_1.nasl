# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843297");
  script_cve_id("CVE-2016-7914", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7487", "CVE-2017-7495", "CVE-2017-7616");
  script_tag(name:"creation_date", value:"2017-08-29 06:05:48 +0000 (Tue, 29 Aug 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-23 16:38:45 +0000 (Tue, 23 May 2017)");

  script_name("Ubuntu: Security Advisory (USN-3406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3406-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3406-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-3406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an out of bounds read vulnerability existed in the
associative array implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or expose
sensitive information. (CVE-2016-7914)

It was discovered that a NULL pointer dereference existed in the Direct
Rendering Manager (DRM) driver for VMWare devices in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-7261)

It was discovered that the USB Cypress HID drivers for the Linux kernel did
not properly validate reported information from the device. An attacker
with physical access could use this to expose sensitive information (kernel
memory). (CVE-2017-7273)

A reference count bug was discovered in the Linux kernel ipx protocol
stack. A local attacker could exploit this flaw to cause a denial of
service or possibly other unspecified problems. (CVE-2017-7487)

Huang Weller discovered that the ext4 filesystem implementation in the
Linux kernel mishandled a needs-flushing-before-commit list. A local
attacker could use this to expose sensitive information. (CVE-2017-7495)

It was discovered that an information leak existed in the set_mempolicy and
mbind compat syscalls in the Linux kernel. A local attacker could use this
to expose sensitive information (kernel memory). (CVE-2017-7616)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-generic", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-generic-lpae", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-lowlatency", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-powerpc-e500", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-powerpc-e500mc", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-powerpc-smp", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-powerpc64-emb", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-129-powerpc64-smp", ver:"3.13.0-129.178", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"3.13.0.129.138", rls:"UBUNTU14.04 LTS"))) {
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
