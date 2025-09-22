# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6728.2");
  script_cve_id("CVE-2023-49288", "CVE-2023-5824", "CVE-2024-23638", "CVE-2024-25111", "CVE-2024-25617");
  script_tag(name:"creation_date", value:"2024-04-12 04:08:49 +0000 (Fri, 12 Apr 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 13:51:19 +0000 (Thu, 09 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6728-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6728-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6728-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2060880");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the USN-6728-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6728-1 fixed vulnerabilities in Squid. The fix for CVE-2023-5824 caused
Squid to crash in certain environments on Ubuntu 20.04 LTS. The problematic
fix has been reverted pending further investigation.

We apologize for the inconvenience.

Original advisory details:

 Joshua Rogers discovered that Squid incorrectly handled collapsed
 forwarding. A remote attacker could possibly use this issue to cause Squid
 to crash, resulting in a denial of service. This issue only affected Ubuntu
 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-49288)

 Joshua Rogers discovered that Squid incorrectly handled certain structural
 elements. A remote attacker could possibly use this issue to cause Squid to
 crash, resulting in a denial of service. (CVE-2023-5824)

 Joshua Rogers discovered that Squid incorrectly handled Cache Manager error
 responses. A remote trusted client can possibly use this issue to cause
 Squid to crash, resulting in a denial of service. (CVE-2024-23638)

 Joshua Rogers discovered that Squid incorrectly handled the HTTP Chunked
 decoder. A remote attacker could possibly use this issue to cause Squid to
 stop responding, resulting in a denial of service. (CVE-2024-25111)

 Joshua Rogers discovered that Squid incorrectly handled HTTP header
 parsing. A remote trusted client can possibly use this issue to cause
 Squid to crash, resulting in a denial of service. (CVE-2024-25617)");

  script_tag(name:"affected", value:"'squid' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"4.10-1ubuntu1.11", rls:"UBUNTU20.04 LTS"))) {
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
