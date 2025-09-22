# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840379");
  script_cve_id("CVE-2009-0692");
  script_tag(name:"creation_date", value:"2010-01-29 13:09:25 +0000 (Fri, 29 Jan 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-803-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-803-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-803-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp3' package(s) announced via the USN-803-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-803-1 fixed a vulnerability in Dhcp. Due to an error, the patch to
fix the vulnerability was not properly applied on Ubuntu 8.10 and higher.
Even with the patch improperly applied, the default compiler options
reduced the vulnerability to a denial of service. Additionally, in Ubuntu
9.04 and higher, users were also protected by the AppArmor dhclient3
profile. This update fixes the problem.

Original advisory details:

 It was discovered that the DHCP client as included in dhcp3 did not verify
 the length of certain option fields when processing a response from an IPv4
 dhcp server. If a user running Ubuntu 6.06 LTS or 8.04 LTS connected to a
 malicious dhcp server, a remote attacker could cause a denial of service or
 execute arbitrary code as the user invoking the program, typically the
 'dhcp' user. For users running Ubuntu 8.10 or 9.04, a remote attacker
 should only be able to cause a denial of service in the DHCP client. In
 Ubuntu 9.04, attackers would also be isolated by the AppArmor dhclient3
 profile.");

  script_tag(name:"affected", value:"'dhcp3' package(s) on Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-1ubuntu2.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client-udeb", ver:"3.1.1-1ubuntu2.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"dhcp-client", ver:"3.1.1-5ubuntu8.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-5ubuntu8.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"dhcp-client", ver:"3.1.2-1ubuntu7.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.2-1ubuntu7.1", rls:"UBUNTU9.10"))) {
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
