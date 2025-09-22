# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845346");
  script_cve_id("CVE-2021-3618");
  script_tag(name:"creation_date", value:"2022-04-29 01:00:49 +0000 (Fri, 29 Apr 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 20:46:57 +0000 (Mon, 04 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5371-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5371-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5371-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the USN-5371-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5371-1 fixed several vulnerabilities in nginx.
This update provides the fix for CVE-2021-3618 for Ubuntu 22.04 LTS.

Original advisory details:

 It was discovered that nginx Lua module mishandled certain inputs.
 An attacker could possibly use this issue to perform an HTTP Request
 Smuggling attack. This issue was fixed for Ubuntu 18.04 LTS and
 Ubuntu 20.04 LTS. (CVE-2020-11724)

 It was discovered that nginx Lua module mishandled certain inputs.
 An attacker could possibly use this issue to disclose sensitive
 information. This issue only affects Ubuntu 18.04 LTS and
 Ubuntu 20.04 LTS. (CVE-2020-36309)

 It was discovered that nginx mishandled the use of
 compatible certificates among multiple encryption protocols.
 If a remote attacker were able to intercept the communication,
 this issue could be used to redirect traffic between subdomains.
 (CVE-2021-3618)");

  script_tag(name:"affected", value:"'nginx' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nginx-core", ver:"1.18.0-6ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.18.0-6ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.18.0-6ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
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
