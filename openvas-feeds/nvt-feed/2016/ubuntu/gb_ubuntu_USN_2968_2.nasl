# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842743");
  script_cve_id("CVE-2015-7515", "CVE-2015-8830", "CVE-2016-0774", "CVE-2016-0821", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3689");
  script_tag(name:"creation_date", value:"2016-05-10 03:21:30 +0000 (Tue, 10 May 2016)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 16:46:36 +0000 (Thu, 14 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2968-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2968-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2968-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2968-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2968-1 fixed vulnerabilities in the Linux kernel for Ubuntu
14.04 LTS. This update provides the corresponding updates for the
Linux Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for
Ubuntu 12.04 LTS.

Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7515)

Ben Hawkes discovered that the Linux kernel's AIO interface allowed single
writes greater than 2GB, which could cause an integer overflow when writing
to certain filesystems, socket or device types. A local attacker could this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2015-8830)

It was discovered that the Linux kernel did not keep accurate track of pipe
buffer details when error conditions occurred, due to an incomplete fix for
CVE-2015-1805. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code with administrative
privileges. (CVE-2016-0774)

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
cause a denial of service (system ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-86-generic", ver:"3.13.0-86.130~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-86-generic-lpae", ver:"3.13.0-86.130~precise1", rls:"UBUNTU12.04 LTS"))) {
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
