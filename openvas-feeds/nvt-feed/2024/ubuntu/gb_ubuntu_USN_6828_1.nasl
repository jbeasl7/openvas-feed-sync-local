# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6828.1");
  script_cve_id("CVE-2023-47233", "CVE-2023-52434", "CVE-2023-52435", "CVE-2023-52447", "CVE-2023-52486", "CVE-2023-52489", "CVE-2023-52491", "CVE-2023-52492", "CVE-2023-52493", "CVE-2023-52494", "CVE-2023-52497", "CVE-2023-52498", "CVE-2023-52530", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52588", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52604", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52608", "CVE-2023-52614", "CVE-2023-52615", "CVE-2023-52616", "CVE-2023-52617", "CVE-2023-52618", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52627", "CVE-2023-52631", "CVE-2023-52633", "CVE-2023-52635", "CVE-2023-52637", "CVE-2023-52638", "CVE-2023-52640", "CVE-2023-52641", "CVE-2023-52642", "CVE-2023-52643", "CVE-2023-52644", "CVE-2023-52645", "CVE-2023-52650", "CVE-2023-52652", "CVE-2023-52656", "CVE-2023-52662", "CVE-2023-6270", "CVE-2023-7042", "CVE-2024-0841", "CVE-2024-1151", "CVE-2024-2201", "CVE-2024-22099", "CVE-2024-23849", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26592", "CVE-2024-26593", "CVE-2024-26594", "CVE-2024-26600", "CVE-2024-26601", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26606", "CVE-2024-26608", "CVE-2024-26610", "CVE-2024-26614", "CVE-2024-26615", "CVE-2024-26622", "CVE-2024-26625", "CVE-2024-26627", "CVE-2024-26635", "CVE-2024-26636", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26644", "CVE-2024-26645", "CVE-2024-26651", "CVE-2024-26659", "CVE-2024-26660", "CVE-2024-26663", "CVE-2024-26664", "CVE-2024-26665", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26676", "CVE-2024-26679", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26695", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26698", "CVE-2024-26702", "CVE-2024-26704", "CVE-2024-26707", "CVE-2024-26712", "CVE-2024-26715", "CVE-2024-26717", "CVE-2024-26720", "CVE-2024-26722", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26736", "CVE-2024-26737", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26748", "CVE-2024-26749", "CVE-2024-26750", "CVE-2024-26751", "CVE-2024-26752", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26769", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26776", "CVE-2024-26777", "CVE-2024-26778", "CVE-2024-26779", "CVE-2024-26782", "CVE-2024-26787", "CVE-2024-26788", "CVE-2024-26790", "CVE-2024-26791", "CVE-2024-26792", "CVE-2024-26793", "CVE-2024-26795", "CVE-2024-26798", "CVE-2024-26801", "CVE-2024-26802", "CVE-2024-26803", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26808", "CVE-2024-26809", "CVE-2024-26816", "CVE-2024-26820", "CVE-2024-26825", "CVE-2024-26826", "CVE-2024-26829", "CVE-2024-26833", "CVE-2024-26835", "CVE-2024-26838", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26843", "CVE-2024-26845", "CVE-2024-26846", "CVE-2024-26851", "CVE-2024-26852", "CVE-2024-26855", "CVE-2024-26856", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26863", "CVE-2024-26870", "CVE-2024-26872", "CVE-2024-26874", "CVE-2024-26875", "CVE-2024-26877", "CVE-2024-26878", "CVE-2024-26879", "CVE-2024-26880", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26889", "CVE-2024-26891", "CVE-2024-26894", "CVE-2024-26895", "CVE-2024-26897", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26906", "CVE-2024-26907", "CVE-2024-26910", "CVE-2024-26915", "CVE-2024-26916", "CVE-2024-26920", "CVE-2024-27024", "CVE-2024-27028", "CVE-2024-27030", "CVE-2024-27034", "CVE-2024-27037", "CVE-2024-27038", "CVE-2024-27039", "CVE-2024-27043", "CVE-2024-27044", "CVE-2024-27045", "CVE-2024-27046", "CVE-2024-27047", "CVE-2024-27051", "CVE-2024-27052", "CVE-2024-27053", "CVE-2024-27054", "CVE-2024-27065", "CVE-2024-27073", "CVE-2024-27074", "CVE-2024-27075", "CVE-2024-27076", "CVE-2024-27077", "CVE-2024-27078", "CVE-2024-27388", "CVE-2024-27390", "CVE-2024-27403", "CVE-2024-27405", "CVE-2024-27410", "CVE-2024-27412", "CVE-2024-27413", "CVE-2024-27414", "CVE-2024-27415", "CVE-2024-27416", "CVE-2024-27417", "CVE-2024-27419", "CVE-2024-27431", "CVE-2024-27432", "CVE-2024-27436", "CVE-2024-35811", "CVE-2024-35828", "CVE-2024-35829", "CVE-2024-35830", "CVE-2024-35844", "CVE-2024-35845");
  script_tag(name:"creation_date", value:"2024-06-12 04:07:57 +0000 (Wed, 12 Jun 2024)");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Ubuntu: Security Advisory (USN-6828-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6828-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6828-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg-5.15' package(s) announced via the USN-6828-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zheng Wang discovered that the Broadcom FullMAC WLAN driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could possibly
use this to cause a denial of service (system crash). (CVE-2023-47233)

It was discovered that the ATA over Ethernet (AoE) driver in the Linux
kernel contained a race condition, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2023-6270)

It was discovered that the Atheros 802.11ac wireless driver did not
properly validate certain data structures, leading to a NULL pointer
dereference. An attacker could possibly use this to cause a denial of
service. (CVE-2023-7042)

It was discovered that the HugeTLB file system component of the Linux
Kernel contained a NULL pointer dereference vulnerability. A privileged
attacker could possibly use this to to cause a denial of service.
(CVE-2024-0841)

It was discovered that the Open vSwitch implementation in the Linux kernel
could overflow its stack during recursive action operations under certain
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2024-1151)

Sander Wiebing, Alvise de Faveri Tron, Herbert Bos, and Cristiano Giuffrida
discovered that the Linux kernel mitigations for the initial Branch History
Injection vulnerability (CVE-2022-0001) were insufficient for Intel
processors. A local attacker could potentially use this to expose sensitive
information. (CVE-2024-2201)

Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux
Kernel contained a race condition, leading to a NULL pointer dereference.
An attacker could possibly use this to cause a denial of service (system
crash). (CVE-2024-22099)

Chenyuan Yang discovered that the RDS Protocol implementation in the Linux
kernel contained an out-of-bounds read vulnerability. An attacker could use
this to possibly cause a denial of service (system crash). (CVE-2024-23849)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - S390 architecture,
 - Core kernel,
 - x86 architecture,
 - Block layer subsystem,
 - ACPI drivers,
 - Android drivers,
 - Power management core,
 - Bus devices,
 - Hardware random number generator core,
 - Clock framework and drivers,
 - CPU frequency scaling framework,
 - Cryptographic API,
 - Device frequency scaling framework,
 - DMA engine subsystem,
 - ARM SCMI message protocol,
 - EFI core,
 - GPU drivers,
 - HID subsystem,
 - Hardware monitoring drivers,
 - I2C subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - IIO Magnetometer sensors drivers,
 - InfiniBand drivers,
 - IOMMU ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1058-intel-iotg", ver:"5.15.0-1058.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.15.0.1058.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1058.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
