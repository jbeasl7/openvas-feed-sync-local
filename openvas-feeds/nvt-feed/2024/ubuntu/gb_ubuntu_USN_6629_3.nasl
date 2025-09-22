# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6629.3");
  script_cve_id("CVE-2022-31116", "CVE-2022-31117");
  script_tag(name:"creation_date", value:"2024-02-15 04:08:41 +0000 (Thu, 15 Feb 2024)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 11:32:25 +0000 (Thu, 14 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-6629-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6629-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6629-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ujson' package(s) announced via the USN-6629-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6629-1 fixed vulnerabilities in UltraJSON.
This update provides the corresponding updates for Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that UltraJSON incorrectly handled certain input with
 a large amount of indentation. An attacker could possibly use this issue
 to crash the program, resulting in a denial of service. (CVE-2021-45958)

 Jake Miller discovered that UltraJSON incorrectly decoded certain
 characters. An attacker could possibly use this issue to cause key
 confusion and overwrite values in dictionaries. (CVE-2022-31116)

 It was discovered that UltraJSON incorrectly handled an error when
 reallocating a buffer for string decoding. An attacker could possibly
 use this issue to corrupt memory. (CVE-2022-31117)");

  script_tag(name:"affected", value:"'ujson' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-ujson", ver:"1.35-4ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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
