# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6885.3");
  script_cve_id("CVE-2024-38474", "CVE-2024-38475", "CVE-2024-38476", "CVE-2024-38477");
  script_tag(name:"creation_date", value:"2024-09-19 04:07:37 +0000 (Thu, 19 Sep 2024)");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-21 15:08:56 +0000 (Wed, 21 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-6885-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6885-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6885-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-6885-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6885-1 fixed several vulnerabilities in Apache. This update provides
the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 Orange Tsai discovered that the Apache HTTP Server mod_rewrite module
 incorrectly handled certain substitutions. A remote attacker could
 possibly use this issue to execute scripts in directories not directly
 reachable by any URL, or cause a denial of service. Some environments
 may require using the new UnsafeAllow3F flag to handle unsafe
 substitutions. (CVE-2024-38474, CVE-2024-38475)

 Orange Tsai discovered that the Apache HTTP Server incorrectly handled
 certain response headers. A remote attacker could possibly use this issue
 to obtain sensitive information, execute local scripts, or perform SSRF
 attacks. (CVE-2024-38476)

 Orange Tsai discovered that the Apache HTTP Server mod_proxy module
 incorrectly handled certain requests. A remote attacker could possibly use
 this issue to cause the server to crash, resulting in a denial of service.
 (CVE-2024-38477)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.18-2ubuntu3.17+esm13", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.27+esm3", rls:"UBUNTU18.04 LTS"))) {
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
