# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6628.2");
  script_cve_id("CVE-2023-32250", "CVE-2023-32252", "CVE-2023-32257", "CVE-2023-34324", "CVE-2023-35827", "CVE-2023-46813", "CVE-2023-6039", "CVE-2023-6040", "CVE-2023-6176", "CVE-2023-6606", "CVE-2023-6622", "CVE-2023-6817", "CVE-2023-6931", "CVE-2023-6932", "CVE-2024-0193", "CVE-2024-0641");
  script_tag(name:"creation_date", value:"2024-02-16 04:08:40 +0000 (Fri, 16 Feb 2024)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 13:54:18 +0000 (Wed, 02 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6628-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6628-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6628-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg-5.15' package(s) announced via the USN-6628-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Quentin Minster discovered that a race condition existed in the KSMBD
implementation in the Linux kernel when handling sessions operations. A
remote attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-32250, CVE-2023-32252,
CVE-2023-32257)

Marek Marczykowski-Gorecki discovered that the Xen event channel
infrastructure implementation in the Linux kernel contained a race
condition. An attacker in a guest VM could possibly use this to cause a
denial of service (paravirtualized device unavailability). (CVE-2023-34324)

Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver
in the Linux kernel during device removal. A privileged attacker could use
this to cause a denial of service (system crash). (CVE-2023-35827)

Tom Dohrmann discovered that the Secure Encrypted Virtualization (SEV)
implementation for AMD processors in the Linux kernel contained a race
condition when accessing MMIO registers. A local attacker in a SEV guest VM
could possibly use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-46813)

It was discovered that the Microchip USB Ethernet driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could use this to
cause a denial of service (system crash). (CVE-2023-6039)

Lin Ma discovered that the netfilter subsystem in the Linux kernel did not
properly validate network family support while creating a new netfilter
table. A local attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2023-6040)

It was discovered that the TLS subsystem in the Linux kernel did not
properly perform cryptographic operations in some situations, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-6176)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate the server frame size in certain
situation, leading to an out-of-bounds read vulnerability. An attacker
could use this to construct a malicious CIFS image that, when operated on,
could cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2023-6606)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle dynset expressions passed from userspace, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2023-6622)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle inactive elements in its PIPAPO data structure, leading
to a use-after-free vulnerability. A local attacker could use this to cause
a denial ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-intel-iotg-5.15' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1048-intel-iotg", ver:"5.15.0-1048.54~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.15.0.1048.54~20.04.38", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1048.54~20.04.38", rls:"UBUNTU20.04 LTS"))) {
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
