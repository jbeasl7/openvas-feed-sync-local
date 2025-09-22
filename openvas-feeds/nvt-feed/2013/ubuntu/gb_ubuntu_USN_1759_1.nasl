# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841361");
  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2275");
  script_tag(name:"creation_date", value:"2013-03-15 04:36:08 +0000 (Fri, 15 Mar 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1759-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1759-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1759-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-1759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Puppet agents incorrectly handled certain kick
connections in a non-default configuration. An attacker on an authenticated
client could use this issue to possibly execute arbitrary code.
(CVE-2013-1653)

It was discovered that Puppet incorrectly handled certain catalog requests.
An attacker on an authenticated client could use this issue to possibly
execute arbitrary code on the master. (CVE-2013-1640)

It was discovered that Puppet incorrectly handled certain client requests.
An attacker on an authenticated client could use this issue to possibly
perform unauthorized actions. (CVE-2013-1652)

It was discovered that Puppet incorrectly handled certain SSL connections.
An attacker could use this issue to possibly downgrade connections to
SSLv2. (CVE-2013-1654)

It was discovered that Puppet incorrectly handled serialized attributes.
An attacker on an authenticated client could use this issue to possibly
cause a denial of service, or execute arbitrary. (CVE-2013-1655)

It was discovered that Puppet incorrectly handled submitted reports.
An attacker on an authenticated node could use this issue to possibly
submit a report for any other node. (CVE-2013-2275)");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.1-1ubuntu3.8", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.11-1ubuntu2.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.18-1ubuntu1.1", rls:"UBUNTU12.10"))) {
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
