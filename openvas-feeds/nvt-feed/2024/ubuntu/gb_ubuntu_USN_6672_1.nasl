# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6672.1");
  script_cve_id("CVE-2023-23919", "CVE-2023-23920", "CVE-2023-2650");
  script_tag(name:"creation_date", value:"2024-03-05 04:08:40 +0000 (Tue, 05 Mar 2024)");
  script_version("2024-03-05T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-03-05 05:05:54 +0000 (Tue, 05 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:17:19 +0000 (Fri, 03 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6672-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6672-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6672-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-6672-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Morgan Jones discovered that Node.js incorrectly handled certain inputs that
leads to false positive errors during some cryptographic operations. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 23.10. (CVE-2023-23919)

It was discovered that Node.js incorrectly handled certain inputs leaded to a
untrusted search path vulnerability. If a user or an automated system were
tricked into opening a specially crafted input file, a remote attacker could
possibly use this issue to perform a privilege escalation. (CVE-2023-23920)

Matt Caswell discovered that Node.js incorrectly handled certain inputs with
specially crafted ASN.1 object identifiers or data containing them. If a user
or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 22.04 LTS. (CVE-2023-2650)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.19.0~dfsg-3ubuntu1.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.19.0~dfsg-3ubuntu1.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.9~dfsg-1ubuntu3.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.9~dfsg-1ubuntu3.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode108", ver:"18.13.0+dfsg1-1ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"18.13.0+dfsg1-1ubuntu2.1", rls:"UBUNTU23.10"))) {
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
