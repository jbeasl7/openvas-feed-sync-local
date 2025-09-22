# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841776");
  script_cve_id("CVE-2012-6151", "CVE-2014-2284", "CVE-2014-2285", "CVE-2014-2310");
  script_tag(name:"creation_date", value:"2014-04-15 04:13:16 +0000 (Tue, 15 Apr 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2166-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2166-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the USN-2166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ken Farnen discovered that Net-SNMP incorrectly handled AgentX timeouts. A
remote attacker could use this issue to cause the server to crash or to
hang, resulting in a denial of service. (CVE-2012-6151)

It was discovered that the Net-SNMP ICMP-MIB incorrectly validated input. A
remote attacker could use this issue to cause the server to crash,
resulting in a denial of service. This issue only affected Ubuntu 13.10.
(CVE-2014-2284)

Viliam Pucik discovered that the Net-SNMP perl trap handler incorrectly
handled NULL arguments. A remote attacker could use this issue to cause the
server to crash, resulting in a denial of service. (CVE-2014-2285)

It was discovered that Net-SNMP incorrectly handled AgentX multi-object
requests. A remote attacker could use this issue to cause the server to
hang, resulting in a denial of service. This issue only affected Ubuntu
10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 12.10. (CVE-2014-2310)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp15", ver:"5.4.2.1~dfsg0ubuntu1-0ubuntu2.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp15", ver:"5.4.3~dfsg-2.4ubuntu1.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp15", ver:"5.4.3~dfsg-2.5ubuntu1.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp30", ver:"5.7.2~dfsg-8ubuntu1.1", rls:"UBUNTU13.10"))) {
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
