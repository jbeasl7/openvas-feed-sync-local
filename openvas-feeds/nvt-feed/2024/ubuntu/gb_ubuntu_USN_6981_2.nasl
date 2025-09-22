# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6981.2");
  script_cve_id("CVE-2020-13671", "CVE-2020-28948", "CVE-2020-28949");
  script_tag(name:"creation_date", value:"2024-09-04 04:09:32 +0000 (Wed, 04 Sep 2024)");
  script_version("2024-09-04T05:16:32+0000");
  script_tag(name:"last_modification", value:"2024-09-04 05:16:32 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 15:23:57 +0000 (Thu, 03 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-6981-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6981-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6981-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7' package(s) announced via the USN-6981-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6981-1 fixed vulnerabilities in Drupal. This update provides the
corresponding updates for Ubuntu 14.04 LTS.

Original advisory details:

 It was discovered that Drupal incorrectly sanitized uploaded filenames. A
 remote attacker could possibly use this issue to execute arbitrary code.
 (CVE-2020-13671)

 It was discovered that Drupal incorrectly sanitized archived filenames. A
 remote attacker could possibly use this issue to overwrite arbitrary
 files, or execute arbitrary code. (CVE-2020-28948, CVE-2020-28949)");

  script_tag(name:"affected", value:"'drupal7' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.26-1ubuntu0.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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
