# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7984.1");
  script_cve_id("CVE-2024-47515", "CVE-2024-47516", "CVE-2024-4981", "CVE-2024-4982");
  script_tag(name:"creation_date", value:"2026-02-04 04:32:47 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-04T05:55:03+0000");
  script_tag(name:"last_modification", value:"2026-02-04 05:55:03 +0000 (Wed, 04 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-26 00:15:13 +0000 (Wed, 26 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7984-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7984-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pagure' package(s) announced via the USN-7984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Chauchefoin discovered that Pagure incorrectly handled symbolic
links in Git repositories. A remote attacker could possibly use this
issue to cause Pagure to expose files outside the intended repository
boundaries. (CVE-2024-4981)

Thomas Chauchefoin discovered that Pagure did not properly sanitize path
inputs. A remote attacker could possibly use this issue to read arbitrary
files. (CVE-2024-4982)

Thomas Chauchefoin discovered that Pagure incorrectly handled symbolic
links during repository archiving. A remote attacker could possibly use
this issue to disclose local files on the server. (CVE-2024-47515)

Thomas Chauchefoin discovered that Pagure incorrectly handled certain
inputs. A remote attacker could possibly use this issue to execute
arbitrary code on the server. (CVE-2024-47516)");

  script_tag(name:"affected", value:"'pagure' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"pagure", ver:"5.8.1+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pagure", ver:"5.11.3+dfsg-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pagure", ver:"5.11.3+dfsg-2.1ubuntu0.2", rls:"UBUNTU24.04 LTS"))) {
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
