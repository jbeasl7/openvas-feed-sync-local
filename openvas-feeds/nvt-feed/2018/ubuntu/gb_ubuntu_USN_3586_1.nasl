# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843464");
  script_cve_id("CVE-2016-2774", "CVE-2017-3144", "CVE-2018-5732", "CVE-2018-5733");
  script_tag(name:"creation_date", value:"2018-03-02 07:41:48 +0000 (Fri, 02 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-07 21:08:53 +0000 (Thu, 07 Feb 2019)");

  script_name("Ubuntu: Security Advisory (USN-3586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3586-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3586-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'isc-dhcp' package(s) announced via the USN-3586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Konstantin Orekhov discovered that the DHCP server incorrectly handled a
large number of concurrent TCP sessions. A remote attacker could possibly
use this issue to cause a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-2774)

It was discovered that the DHCP server incorrectly handled socket
descriptors. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2017-3144)

Felix Wilhelm discovered that the DHCP client incorrectly handled certain
malformed responses. A remote attacker could use this issue to cause the
DHCP client to crash, resulting in a denial of service, or possibly execute
arbitrary code. In the default installation, attackers would be isolated by
the dhclient AppArmor profile. (CVE-2018-5732)

Felix Wilhelm discovered that the DHCP server incorrectly handled reference
counting. A remote attacker could possibly use this issue to cause the DHCP
server to crash, resulting in a denial of service. (CVE-2018-5733)");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.2.4-7ubuntu12.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.2.4-7ubuntu12.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.2.4-7ubuntu12.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.2.4-7ubuntu12.12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.3-5ubuntu12.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.3.3-5ubuntu12.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.3-5ubuntu12.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.3.3-5ubuntu12.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.5-3ubuntu2.2", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.3.5-3ubuntu2.2", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.5-3ubuntu2.2", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.3.5-3ubuntu2.2", rls:"UBUNTU17.10"))) {
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
