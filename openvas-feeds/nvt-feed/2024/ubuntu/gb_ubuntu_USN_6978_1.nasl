# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6978.1");
  script_cve_id("CVE-2016-3674", "CVE-2020-26217", "CVE-2020-26258", "CVE-2020-26259", "CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351");
  script_tag(name:"creation_date", value:"2024-08-23 04:09:10 +0000 (Fri, 23 Aug 2024)");
  script_version("2024-08-23T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 19:39:32 +0000 (Thu, 25 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-6978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6978-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6978-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxstream-java' package(s) announced via the USN-6978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that XStream incorrectly handled parsing of certain
crafted XML documents. A remote attacker could possibly use this issue to
read arbitrary files. (CVE-2016-3674)

Zhihong Tian and Hui Lu found that XStream was vulnerable to remote code
execution. A remote attacker could run arbitrary shell commands by
manipulating the processed input stream. (CVE-2020-26217)

It was discovered that XStream was vulnerable to server-side forgery
attacks. A remote attacker could request data from internal resources
that are not publicly available only by manipulating the processed input
stream. (CVE-2020-26258)

It was discovered that XStream was vulnerable to arbitrary file deletion
on the local host. A remote attacker could use this to delete arbitrary
known files on the host as long as the executing process had sufficient
rights only by manipulating the processed input stream. (CVE-2020-26259)

It was discovered that XStream was vulnerable to denial of service,
arbitrary code execution, arbitrary file deletion and server-side forgery
attacks. A remote attacker could cause any of those issues by
manipulating the processed input stream. (CVE-2021-21341, CVE-2021-21342,
CVE-2021-21343, CVE-2021-21344, CVE-2021-21345, CVE-2021-21346,
CVE-2021-21347, CVE-2021-21348, CVE-2021-21349, CVE-2021-21350,
CVE-2021-21351)");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.7-1ubuntu0.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.8-1ubuntu0.1+esm3", rls:"UBUNTU16.04 LTS"))) {
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
