# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7352.2");
  script_cve_id("CVE-2022-27406", "CVE-2025-27363");
  script_tag(name:"creation_date", value:"2025-03-19 04:04:22 +0000 (Wed, 19 Mar 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-07 16:00:55 +0000 (Wed, 07 May 2025)");

  script_name("Ubuntu: Security Advisory (USN-7352-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7352-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7352-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the USN-7352-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7352-1 fixed a vulnerability in FreeType. This update provides the
corresponding updates for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. This
update also fixes an additional vulnerability in Ubuntu 14.04 LTS.

Original advisory details:

 It was discovered that FreeType incorrectly handled certain memory
 operations when parsing font subglyph structures. A remote attacker could
 use this issue to cause FreeType to crash, resulting in a denial of
 service, or possibly execute arbitrary code. This issue only affected
 Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2025-27363)

Additional advisory details:

 It was discovered that FreeType incorrectly handled certain memory
 operations during typical execution. An attacker could possibly use
 this issue to cause FreeType to crash, resulting in a denial of
 service. This issue only affected Ubuntu 14.04 LTS. (CVE-2022-27406)");

  script_tag(name:"affected", value:"'freetype' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.5.2-1ubuntu2.8+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.6.1-0.1ubuntu2.5+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.8.1-2ubuntu2.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
