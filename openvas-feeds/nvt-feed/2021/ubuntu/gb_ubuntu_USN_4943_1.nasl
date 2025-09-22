# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844937");
  script_cve_id("CVE-2020-26217", "CVE-2020-26258", "CVE-2020-26259", "CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343", "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347", "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351");
  script_tag(name:"creation_date", value:"2021-05-12 03:01:26 +0000 (Wed, 12 May 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 19:39:32 +0000 (Thu, 25 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4943-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4943-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4943-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxstream-java' package(s) announced via the USN-4943-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhihong Tian and Hui Lu found that XStream was vulnerable to remote code
execution. A remote attacker could run arbitrary shell commands by
manipulating the processed input stream. This issue affected only affected
Ubuntu 20.10. (CVE-2020-26217)

It was discovered that XStream was vulnerable to server-side forgery attacks.
A remote attacker could request data from internal resources that are not
publicly available only by manipulating the processed input stream. This
issue only affected Ubuntu 20.10. (CVE-2020-26258)

It was discovered that XStream was vulnerable to arbitrary file deletion on
the local host. A remote attacker could use this to delete arbitrary known
files on the host as long as the executing process had sufficient rights only
by manipulating the processed input stream. This issue only affected
Ubuntu 20.10. (CVE-2020-26259)

It was discovered that XStream was vulnerable to denial of service,
arbitrary code execution, arbitrary file deletion and server-side forgery
attacks. A remote attacker could cause any of those issues by manipulating
the processed input stream. (CVE-2021-21341, CVE-2021-21342, CVE-2021-21343
CVE-2021-21344, CVE-2021-21345, CVE-2021-21346, CVE-2021-21347,
CVE-2021-21348, CVE-2021-21349, CVE-2021-21350, CVE-2021-21351)");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-2ubuntu0.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.15-1ubuntu0.1", rls:"UBUNTU21.04"))) {
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
