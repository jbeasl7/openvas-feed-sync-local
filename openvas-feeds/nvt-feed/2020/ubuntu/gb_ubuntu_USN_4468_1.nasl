# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844545");
  script_cve_id("CVE-2020-8620", "CVE-2020-8621", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_tag(name:"creation_date", value:"2020-08-22 03:00:18 +0000 (Sat, 22 Aug 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 17:55:39 +0000 (Wed, 26 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4468-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4468-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-4468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emanuel Almeida discovered that Bind incorrectly handled certain TCP
payloads. A remote attacker could possibly use this issue to cause Bind to
crash, resulting in a denial of service. This issue only affected Ubuntu
20.04 LTS. (CVE-2020-8620)

Joseph Gullo discovered that Bind incorrectly handled QNAME minimization
when used in certain configurations. A remote attacker could possibly use
this issue to cause Bind to crash, resulting in a denial of service. This
issue only affected Ubuntu 20.04 LTS. (CVE-2020-8621)

Dave Feldman, Jeff Warren, and Joel Cunningham discovered that Bind
incorrectly handled certain truncated responses to a TSIG-signed request. A
remote attacker could possibly use this issue to cause Bind to crash,
resulting in a denial of service. (CVE-2020-8622)

Lyu Chiy discovered that Bind incorrectly handled certain queries. A remote
attacker could possibly use this issue to cause Bind to crash, resulting in
a denial of service. (CVE-2020-8623)

Joop Boonen discovered that Bind incorrectly handled certain subdomain
update-policy rules. A remote attacker granted privileges to change certain
parts of a zone could use this issue to change other contents of the zone,
contrary to expectations. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-8624)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.10.3.dfsg.P4-8ubuntu1.17", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.3+dfsg-1ubuntu1.13", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.16.1-0ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
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
