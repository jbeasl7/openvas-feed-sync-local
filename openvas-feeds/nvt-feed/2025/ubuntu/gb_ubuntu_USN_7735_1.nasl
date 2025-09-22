# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7735.1");
  script_cve_id("CVE-2023-28755", "CVE-2025-24294");
  script_tag(name:"creation_date", value:"2025-09-05 04:04:35 +0000 (Fri, 05 Sep 2025)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 17:17:09 +0000 (Tue, 30 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-7735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7735-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7735-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygems' package(s) announced via the USN-7735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that RubyGems incorrectly handled certain regular
expressions. An attacker could use this issue to cause RubyGems to crash,
resulting in a denial of service. This issue only affected Ubuntu 22.04
LTS. (CVE-2023-28755)

It was discovered that RubyGems incorrectly handled decompressed domain
names within a DNS packet. An attacker could use this issue to cause
RubyGems to crash, resulting in a denial of service. This issue only
affected Ubuntu 25.04. (CVE-2025-24294)");

  script_tag(name:"affected", value:"'rubygems' package(s) on Ubuntu 22.04, Ubuntu 25.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rubygems", ver:"3.3.5-2ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rubygems", ver:"3.6.3-1ubuntu0.1", rls:"UBUNTU25.04"))) {
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
