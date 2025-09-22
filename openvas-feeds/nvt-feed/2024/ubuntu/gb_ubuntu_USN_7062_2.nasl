# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7062.2");
  script_cve_id("CVE-2024-36474", "CVE-2024-42415");
  script_tag(name:"creation_date", value:"2024-10-22 04:08:09 +0000 (Tue, 22 Oct 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-09 16:44:20 +0000 (Wed, 09 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-7062-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.10");

  script_xref(name:"Advisory-ID", value:"USN-7062-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7062-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgsf' package(s) announced via the USN-7062-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7062-1 fixed vulnerabilities in libgsf. This update provides the
corresponding updates for Ubuntu 24.10.

Original advisory details:

 It was discovered that libgsf incorrectly handled certain Compound
 Document Binary files. If a user or automated system were tricked into
 opening a specially crafted file, a remote attacker could possibly use
 this issue to execute arbitrary code.");

  script_tag(name:"affected", value:"'libgsf' package(s) on Ubuntu 24.10.");

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

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgsf-1-114", ver:"1.14.52-1ubuntu0.1", rls:"UBUNTU24.10"))) {
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
