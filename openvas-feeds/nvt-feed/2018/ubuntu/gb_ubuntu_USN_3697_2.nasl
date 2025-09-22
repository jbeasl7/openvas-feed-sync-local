# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843573");
  script_cve_id("CVE-2018-1130", "CVE-2018-11508", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7755", "CVE-2018-7757");
  script_tag(name:"creation_date", value:"2018-07-03 03:47:03 +0000 (Tue, 03 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-08 18:38:45 +0000 (Wed, 08 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3697-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3697-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3697-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem' package(s) announced via the USN-3697-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a null pointer dereference vulnerability existed in
the DCCP protocol implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash). (CVE-2018-1130)

Jann Horn discovered that the 32 bit adjtimex() syscall implementation for
64 bit Linux kernels did not properly initialize memory returned to user
space in some situations. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-11508)

Wang Qize discovered that an information disclosure vulnerability existed
in the SMBus driver for ACPI Embedded Controllers in the Linux kernel. A
local attacker could use this to expose sensitive information (kernel
pointer addresses). (CVE-2018-5750)

It was discovered that the SCTP Protocol implementation in the Linux kernel
did not properly validate userspace provided payload lengths in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2018-5803)

It was discovered that an integer overflow error existed in the futex
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2018-6927)

It was discovered that an information leak vulnerability existed in the
floppy driver in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2018-7755)

It was discovered that a memory leak existed in the SAS driver subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2018-7757)");

  script_tag(name:"affected", value:"'linux-oem' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1031-oem", ver:"4.13.0-1031.35", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.13.0.1031.36", rls:"UBUNTU16.04 LTS"))) {
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
