# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7659.1");
  script_cve_id("CVE-2020-26247", "CVE-2022-29181", "CVE-2022-40303");
  script_tag(name:"creation_date", value:"2025-07-23 04:17:24 +0000 (Wed, 23 Jul 2025)");
  script_version("2025-07-23T05:44:57+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:57 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 02:12:45 +0000 (Tue, 07 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-7659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7659-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7659-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-nokogiri' package(s) announced via the USN-7659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered Nokogiri did not correctly parse XML Schemas.
If a user or automated system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-26247)

Agustin Gianni discovered that Nokogiri did not correctly parse
XML and HTML files. If a user or automated system were tricked into
opening a specially crafted file, an attacker could possibly use this
issue to cause a denial of service or leak sensitive information.
(CVE-2022-29181)");

  script_tag(name:"affected", value:"'ruby-nokogiri' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-nokogiri", ver:"1.10.7+dfsg1-2ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-nokogiri", ver:"1.13.1+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
