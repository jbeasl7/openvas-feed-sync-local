# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845162");
  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2020-25718", "CVE-2020-25719", "CVE-2020-25721", "CVE-2020-25722", "CVE-2021-23192", "CVE-2021-3671", "CVE-2021-3738");
  script_tag(name:"creation_date", value:"2021-12-14 02:00:33 +0000 (Tue, 14 Dec 2021)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 14:59:45 +0000 (Thu, 10 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5142-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|21\.04|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5142-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5142-3");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=14922");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1950363");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25717.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-5142-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5142-1 fixed vulnerabilities in Samba. Some of the upstream changes
introduced a regression in Kerberos authentication in certain environments.

Please see the following upstream bug for more information:
[link moved to references]

This update fixes the problem.

Original advisory details:

 Stefan Metzmacher discovered that Samba incorrectly handled SMB1 client
 connections. A remote attacker could possibly use this issue to downgrade
 connections to plaintext authentication. (CVE-2016-2124)

 Andrew Bartlett discovered that Samba incorrectly mapping domain users to
 local users. An authenticated attacker could possibly use this issue to
 become root on domain members. (CVE-2020-25717)

 Andrew Bartlett discovered that Samba did not correctly sandbox Kerberos
 tickets issues by an RODC. An RODC could print administrator tickets,
 contrary to expectations. (CVE-2020-25718)

 Andrew Bartlett discovered that Samba incorrectly handled Kerberos tickets.
 Delegated administrators could possibly use this issue to impersonate
 accounts, leading to total domain compromise. (CVE-2020-25719)

 Andrew Bartlett discovered that Samba did not provide stable AD
 identifiers to Kerberos acceptors. (CVE-2020-25721)

 Andrew Bartlett discovered that Samba did not properly check sensitive
 attributes. An authenticated attacker could possibly use this issue to
 escalate privileges. (CVE-2020-25722)

 Stefan Metzmacher discovered that Samba incorrectly handled certain large
 DCE/RPC requests. A remote attacker could possibly use this issue to
 bypass signature requirements. (CVE-2021-23192)

 William Ross discovered that Samba incorrectly handled memory. A remote
 attacker could use this issue to cause Samba to crash, resulting in a
 denial of service, or possibly escalate privileges. (CVE-2021-3738)

 Joseph Sutton discovered that Samba incorrectly handled certain TGS
 requests. An authenticated attacker could possibly use this issue to cause
 Samba to crash, resulting in a denial of service. (CVE-2021-3671)

 The fix for CVE-2020-25717 results in possible behaviour changes that could
 affect certain environments. Please see the upstream advisory for more
 information:

 [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.14+dfsg-0ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.14+dfsg-0ubuntu0.21.04.4", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.13.14+dfsg-0ubuntu0.21.10.4", rls:"UBUNTU21.10"))) {
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
