# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7330.2");
  script_cve_id("CVE-2015-3908", "CVE-2015-6240", "CVE-2016-8614", "CVE-2019-10206", "CVE-2019-14846", "CVE-2019-14904", "CVE-2020-10729", "CVE-2020-1739");
  script_tag(name:"creation_date", value:"2025-03-31 04:04:20 +0000 (Mon, 31 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-17 19:20:44 +0000 (Thu, 17 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-7330-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7330-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7330-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2104925");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the USN-7330-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7330-1 fixed vulnerabilities in Ansible. The update introduced a
regression when attempting to install Ansible on Ubuntu 16.04 LTS.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Ansible did not properly verify certain fields
 of X.509 certificates. An attacker could possibly use this issue to
 spoof SSL servers if they were able to intercept network communications.
 This issue only affected Ubuntu 14.04 LTS. (CVE-2015-3908)

 Martin Carpenter discovered that certain connection plugins for Ansible
 did not properly restrict users. An attacker with local access could
 possibly use this issue to escape a restricted environment via symbolic
 links misuse. This issue only affected Ubuntu 14.04 LTS. (CVE-2015-6240)

 Robin Schneider discovered that Ansible's apt_key module did not properly
 verify key fingerprints. A remote attacker could possibly use this issue
 to perform key injection, leading to the access of sensitive information.
 This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
 (CVE-2016-8614)

 It was discovered that Ansible would expose passwords in certain
 instances. An attacker could possibly use specially crafted input
 related to this issue to access sensitive information. This issue only
 affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-10206)

 It was discovered that Ansible incorrectly logged sensitive information.
 An attacker with local access could possibly use this issue to access
 sensitive information. This issue only affected Ubuntu 14.04 LTS, Ubuntu
 16.04 LTS, and Ubuntu 18.04 LTS. (CVE-2019-14846)

 It was discovered that Ansible's solaris_zone module accepted input
 without performing input checking. A remote attacker could possibly use
 this issue to enable the execution of arbitrary code. This issue only
 affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-14904)

 It was discovered that Ansible did not generate sufficiently random
 values, which could lead to the exposure of passwords. An attacker
 could possibly use this issue to access sensitive information. This
 issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
 (CVE-2020-10729)

 It was discovered that Ansible's svn module could disclose passwords to
 users within the same node. An attacker could possibly use this issue to
 access sensitive information. (CVE-2020-1739)");

  script_tag(name:"affected", value:"'ansible' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"2.0.0.2-2ubuntu1.3+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ansible-fireball", ver:"2.0.0.2-2ubuntu1.3+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ansible-node-fireball", ver:"2.0.0.2-2ubuntu1.3+esm6", rls:"UBUNTU16.04 LTS"))) {
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
