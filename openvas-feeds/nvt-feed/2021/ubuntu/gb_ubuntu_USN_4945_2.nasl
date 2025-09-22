# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844949");
  script_cve_id("CVE-2020-25639", "CVE-2021-28038", "CVE-2021-28375", "CVE-2021-28660", "CVE-2021-29265", "CVE-2021-29650", "CVE-2021-30002");
  script_tag(name:"creation_date", value:"2021-05-20 04:46:34 +0000 (Thu, 20 May 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-12 03:54:00 +0000 (Mon, 12 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-4945-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4945-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4945-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi, linux-raspi-5.4' package(s) announced via the USN-4945-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4945-1 fixed vulnerabilities in the Linux kernel for Ubuntu
20.04 LTS and Ubuntu 18.04 LTS. This update provides the corresponding
Linux kernel updates targeted specifically for Raspberry Pi devices
in those same Ubuntu Releases.

Original advisory details:

It was discovered that the Nouveau GPU driver in the Linux kernel did not
properly handle error conditions in some situations. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25639)

Jan Beulich discovered that the Xen netback backend in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-28038)

It was discovered that the fastrpc driver in the Linux kernel did not
prevent user space applications from sending kernel RPC messages. A local
attacker could possibly use this to gain elevated privileges.
(CVE-2021-28375)

It was discovered that the Realtek RTL8188EU Wireless device driver in the
Linux kernel did not properly validate ssid lengths in some situations. An
attacker could use this to cause a denial of service (system crash).
(CVE-2021-28660)

It was discovered that the USB/IP driver in the Linux kernel contained race
conditions during the update of local and shared status. An attacker could
use this to cause a denial of service (system crash). (CVE-2021-29265)

It was discovered that a race condition existed in the netfilter subsystem
of the Linux kernel when replacing tables. A local attacker could use this
to cause a denial of service (system crash). (CVE-2021-29650)

Arnd Bergmann discovered that the video4linux subsystem in the Linux kernel
did not properly deallocate memory in some situations. A local attacker
could use this to cause a denial of service (memory exhaustion).
(CVE-2021-30002)");

  script_tag(name:"affected", value:"'linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1035-raspi", ver:"5.4.0-1035.38~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1035.37", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1035-raspi", ver:"5.4.0-1035.38", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1035.70", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1035.70", rls:"UBUNTU20.04 LTS"))) {
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
