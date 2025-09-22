# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6837.1");
  script_cve_id("CVE-2023-27530", "CVE-2024-25126", "CVE-2024-26141", "CVE-2024-26146");
  script_tag(name:"creation_date", value:"2024-06-18 04:07:56 +0000 (Tue, 18 Jun 2024)");
  script_version("2025-02-17T05:38:47+0000");
  script_tag(name:"last_modification", value:"2025-02-17 05:38:47 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 15:51:42 +0000 (Fri, 14 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6837-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(23\.10|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6837-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6837-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the USN-6837-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Rack incorrectly handled Multipart MIME parsing. A
remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. This issue only affected Ubuntu
23.10. (CVE-2023-27530)

It was discovered that Rack incorrectly parsed certain media types. A
remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. (CVE-2024-25126)

It was discovered that Rack incorrectly handled certain Range headers. A
remote attacker could possibly use this issue to cause Rack to create large
responses, leading to a denial of service. This issue only affected Ubuntu
24.04 LTS. (CVE-2024-26141)

It was discovered that Rack incorrectly handled certain crafted headers. A
remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. This issue only affected Ubuntu
24.04 LTS. (CVE-2024-26146)");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Ubuntu 23.10, Ubuntu 24.04.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU23.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack", ver:"2.2.7-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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
