# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6969.1");
  script_cve_id("CVE-2024-25641", "CVE-2024-29894", "CVE-2024-31443", "CVE-2024-31444", "CVE-2024-31445", "CVE-2024-31458", "CVE-2024-31459", "CVE-2024-31460", "CVE-2024-34340");
  script_tag(name:"creation_date", value:"2024-08-21 04:09:29 +0000 (Wed, 21 Aug 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 20:44:22 +0000 (Wed, 18 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-6969-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6969-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6969-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the USN-6969-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Cacti did not properly apply checks to the 'Package
Import' feature. An attacker could possibly use this issue to perform
arbitrary code execution. This issue only affected Ubuntu 24.04 LTS, Ubuntu
22.04 LTS, Ubuntu 20.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-25641)

It was discovered that Cacti did not properly sanitize values when using
javascript based API. A remote attacker could possibly use this issue to
inject arbitrary javascript code resulting into cross-site scripting
vulnerability. This issue only affected Ubuntu 24.04 LTS. (CVE-2024-29894)

It was discovered that Cacti did not properly sanitize values when managing
data queries. A remote attacker could possibly use this issue to inject
arbitrary javascript code resulting into cross-site scripting
vulnerability. (CVE-2024-31443)

It was discovered that Cacti did not properly sanitize values when reading
tree rules with Automation API. A remote attacker could possibly use this
issue to inject arbitrary javascript code resulting into cross-site
scripting vulnerability. (CVE-2024-31444)

It was discovered that Cacti did not properly sanitize
'get_request_var('filter')' values in the 'api_automation.php' file. A
remote attacker could possibly use this issue to perform SQL injection
attacks. This issue only affected Ubuntu 24.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 20.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-31445)

It was discovered that Cacti did not properly sanitize data stored in
'form_save()' function in the 'graph_template_inputs.php' file. A remote
attacker could possibly use this issue to perform SQL injection attacks.
(CVE-2024-31458)

It was discovered that Cacti did not properly validate the file urls from
the lib/plugin.php file. An attacker could possibly use this issue to
perform arbitrary code execution. (CVE-2024-31459)

It was discovered that Cacti did not properly validate the data stored in
the 'automation_tree_rules.php'. A remote attacker could possibly use this
issue to perform SQL injection attacks. This issue only affected Ubuntu
24.04 LTS, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS and Ubuntu 18.04 LTS.
(CVE-2024-31460)

It was discovered that Cacti did not properly verify the user password.
An attacker could possibly use this issue to bypass authentication
mechanism. This issue only affected Ubuntu 24.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 20.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-34360)");

  script_tag(name:"affected", value:"'cacti' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8b+dfsg-5ubuntu0.2+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8f+ds1-4ubuntu4.16.04.2+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.1.38+ds1-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.2.10+ds1-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.2.19+ds1-2ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.2.26+ds1-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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
