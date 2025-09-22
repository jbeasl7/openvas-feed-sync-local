# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5527.2");
  script_cve_id("CVE-2017-14955", "CVE-2017-9781", "CVE-2021-36563", "CVE-2022-24565");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-29 18:38:39 +0000 (Thu, 29 Jun 2017)");

  script_name("Ubuntu: Security Advisory (USN-5527-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5527-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5527-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'check-mk' package(s) announced via the USN-5527-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5527-1 fixed vulnerabilities in Checkmk. This update provides the
corresponding update for Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that Checkmk incorrectly handled authentication. An attacker
 could possibly use this issue to cause a race condition leading to information
 disclosure. (CVE-2017-14955)

 It was discovered that Checkmk incorrectly handled certain inputs. An attacker
 could use these cross-site scripting issues to inject arbitrary html or
 javascript code to obtain sensitive information including user information,
 session cookies and valid credentials. (CVE-2017-9781, CVE-2021-36563,
 CVE-2021-40906, CVE-2022-24565)");

  script_tag(name:"affected", value:"'check-mk' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"check-mk-livestatus", ver:"1.2.6p12-1ubuntu0.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"check-mk-multisite", ver:"1.2.6p12-1ubuntu0.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"check-mk-server", ver:"1.2.6p12-1ubuntu0.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
