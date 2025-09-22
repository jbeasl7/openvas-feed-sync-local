# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841961");
  script_cve_id("CVE-2013-4357", "CVE-2013-4458", "CVE-2014-0475", "CVE-2014-4043");
  script_tag(name:"creation_date", value:"2014-09-09 03:55:13 +0000 (Tue, 09 Sep 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:31:28 +0000 (Tue, 14 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-2306-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2306-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2306-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1364584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc' package(s) announced via the USN-2306-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2306-1 fixed vulnerabilities in the GNU C Library. On Ubuntu 10.04 LTS,
the fix for CVE-2013-4357 introduced a memory leak in getaddrinfo. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Maksymilian Arciemowicz discovered that the GNU C Library incorrectly
 handled the getaddrinfo() function. An attacker could use this issue to
 cause a denial of service. This issue only affected Ubuntu 10.04 LTS.
 (CVE-2013-4357)

 It was discovered that the GNU C Library incorrectly handled the
 getaddrinfo() function. An attacker could use this issue to cause a denial
 of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
 (CVE-2013-4458)

 Stephane Chazelas discovered that the GNU C Library incorrectly handled
 locale environment variables. An attacker could use this issue to possibly
 bypass certain restrictions such as the ForceCommand restrictions in
 OpenSSH. (CVE-2014-0475)

 David Reid, Glyph Lefkowitz, and Alex Gaynor discovered that the GNU C
 Library incorrectly handled posix_spawn_file_actions_addopen() path
 arguments. An attacker could use this issue to cause a denial of service.
 (CVE-2014-4043)");

  script_tag(name:"affected", value:"'eglibc' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.17", rls:"UBUNTU10.04 LTS"))) {
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
