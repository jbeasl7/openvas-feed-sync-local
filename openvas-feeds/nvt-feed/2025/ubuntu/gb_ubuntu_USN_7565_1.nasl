# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7565.1");
  script_cve_id("CVE-2024-52531", "CVE-2024-52532", "CVE-2025-2784", "CVE-2025-32050", "CVE-2025-32052", "CVE-2025-32053");
  script_tag(name:"creation_date", value:"2025-06-16 04:11:36 +0000 (Mon, 16 Jun 2025)");
  script_version("2025-06-23T05:41:09+0000");
  script_tag(name:"last_modification", value:"2025-06-23 05:41:09 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-03 14:15:44 +0000 (Thu, 03 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7565-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7565-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup2.4' package(s) announced via the USN-7565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsoup did not correctly handle memory while
performing UTF-8 conversions. An attacker could possibly use this issue
to cause a denial of service or execute arbitrary code. This issue only
affected Ubuntu 16.04 LTS. (CVE-2024-52531)

It was discovered that libsoup could enter an infinite loop when reading
certain websocket data. An attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2024-52532)

It was discovered that libsoup could be made to read out of bounds. An
attacker could possibly use this issue to cause applications using
libsoup to crash, resulting in a denial of service. (CVE-2025-2784,
CVE-2025-32050, CVE-2025-32052, CVE-2025-32053)");

  script_tag(name:"affected", value:"'libsoup2.4' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.52.2-1ubuntu0.3+esm4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.62.1-1ubuntu0.4+esm5", rls:"UBUNTU18.04 LTS"))) {
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
