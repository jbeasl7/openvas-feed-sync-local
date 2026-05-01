# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8174.1");
  script_cve_id("CVE-2006-10002", "CVE-2006-10003");
  script_tag(name:"creation_date", value:"2026-04-15 04:57:34 +0000 (Wed, 15 Apr 2026)");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-19 18:16:12 +0000 (Thu, 19 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8174-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8174-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml-parser-perl' package(s) announced via the USN-8174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that XML::Parser incorrectly handled certain multi-byte
UTF-8 characters. If a user or automated system were tricked into
processing specially crafted XML data, a remote attacker could use this
issue to cause XML::Parser to crash, resulting in a denial of service or to
possibly execute arbitrary code. (CVE-2006-10002)

It was discovered that XML::Parser incorrectly handled very deep element
nesting. If a user or automated system were tricked into processing
specially crafted XML data, a remote attacker could use this issue to cause
XML::Parser to crash, resulting in a denial of service or to possibly
execute arbitrary code (CVE-2006-10003)");

  script_tag(name:"affected", value:"'libxml-parser-perl' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxml-parser-perl", ver:"2.46-3ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml-parser-perl", ver:"2.47-1ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml-parser-perl", ver:"2.47-1ubuntu0.25.10.1", rls:"UBUNTU25.10"))) {
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
