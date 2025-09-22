# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842742");
  script_cve_id("CVE-2015-7515", "CVE-2016-0821", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3689");
  script_tag(name:"creation_date", value:"2016-05-10 03:21:28 +0000 (Tue, 10 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 16:46:36 +0000 (Thu, 14 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2971-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  script_xref(name:"Advisory-ID", value:"USN-2971-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2971-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2971-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7515)

Zach Riggle discovered that the Linux kernel's list poison feature did not
take into account the mmap_min_addr value. A local attacker could use this
to bypass the kernel's poison-pointer protection mechanism while attempting
to exploit an existing kernel vulnerability. (CVE-2016-0821)

Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel
did not properly validate USB device descriptors. An attacker with physical
access could use this to cause a denial of service (system crash).
(CVE-2016-2184)

Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the
Linux kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2185)

Ralf Spenneberg discovered that the PowerMate USB driver in the Linux
kernel did not properly validate USB device descriptors. An attacker with
physical access could use this to cause a denial of service (system crash).
(CVE-2016-2186)

Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the
Linux kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2188)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
MCT USB RS232 Converter device driver in the Linux kernel did not properly
validate USB device descriptors. An attacker with physical access could use
this to cause a denial of service (system crash). (CVE-2016-3136)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
Cypress M8 USB device driver in the Linux kernel did not properly validate
USB device descriptors. An attacker with physical access could use this to
cause a denial of service (system crash). (CVE-2016-3137)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
USB abstract device control driver for modems and ISDN adapters did not
validate endpoint descriptors. An attacker with physical access could use
this to cause a denial of service (system crash). (CVE-2016-3138)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
Linux kernel's USB driver for Digi AccelePort serial converters did not
properly validate USB device descriptors. An attacker with physical access
could use this to cause a denial of service (system crash). (CVE-2016-3140)

It was discovered that the IPv4 implementation in the Linux kernel did not
perform the destruction of inet device objects properly. An attacker in a
guest OS could use this to cause a denial of service (networking outage) in
the host OS. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.10.");

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

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-generic", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-generic-lpae", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-lowlatency", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-powerpc-e500mc", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-powerpc-smp", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-powerpc64-emb", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-36-powerpc64-smp", ver:"4.2.0-36.41", rls:"UBUNTU15.10"))) {
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
