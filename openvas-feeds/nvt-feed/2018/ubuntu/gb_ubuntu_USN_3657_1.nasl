# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843534");
  script_cve_id("CVE-2017-17449", "CVE-2017-17975", "CVE-2017-18203", "CVE-2017-18208", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2018-05-23 03:40:50 +0000 (Wed, 23 May 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 15:05:20 +0000 (Fri, 20 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3657-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.10");

  script_xref(name:"Advisory-ID", value:"USN-3657-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3657-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2' package(s) announced via the USN-3657-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the netlink subsystem in the Linux kernel did not
properly restrict observations of netlink messages to the appropriate net
namespace. A local attacker could use this to expose sensitive information
(kernel netlink traffic). (CVE-2017-17449)

Tuba Yavuz discovered that a double-free error existed in the USBTV007
driver of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-17975)

It was discovered that a race condition existed in the Device Mapper
component of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-18203)

It was discovered that an infinite loop could occur in the madvise(2)
implementation in the Linux kernel in certain circumstances. A local
attacker could use this to cause a denial of service (system hang).
(CVE-2017-18208)

Silvio Cesare discovered a buffer overwrite existed in the NCPFS
implementation in the Linux kernel. A remote attacker controlling a
malicious NCPFS server could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-8822)");

  script_tag(name:"affected", value:"'linux-raspi2' package(s) on Ubuntu 17.10.");

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

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1020-raspi2", ver:"4.13.0-1020.21", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.13.0.1020.18", rls:"UBUNTU17.10"))) {
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
