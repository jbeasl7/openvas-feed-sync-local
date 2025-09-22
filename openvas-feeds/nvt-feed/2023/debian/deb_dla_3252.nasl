# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893252");
  script_cve_id("CVE-2020-23226", "CVE-2020-25706", "CVE-2020-8813", "CVE-2022-0730", "CVE-2022-46169");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:25 +0000 (Sun, 01 Jan 2023)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 20:05:03 +0000 (Tue, 06 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3252-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3252-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3252-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cacti");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DLA-3252-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in cacti, a web interface for graphing of monitoring systems, which may result in information disclosure, authentication bypass, or remote code execution.

CVE-2020-8813

Askar discovered that an authenticated guest user with the graph real-time privilege could execute arbitrary code on a server running Cacti, via shell meta-characters in a cookie.

CVE-2020-23226

Jing Chen discovered multiple Cross Site Scripting (XSS) vulnerabilities in several pages, which can lead to information disclosure.

CVE-2020-25706

joelister discovered an Cross Site Scripting (XSS) vulnerability in templates_import.php, which can lead to information disclosure.

CVE-2022-0730

It has been discovered that Cacti authentication can be bypassed when LDAP anonymous binding is enabled.

CVE-2022-46169

Stefan Schiller discovered a command injection vulnerability, allowing an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected (which is likely the case on a production instance) for any monitored device.

For Debian 10 buster, these problems have been fixed in version 1.2.2+ds1-2+deb10u5.

We recommend that you upgrade your cacti packages.

For the detailed security status of cacti please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"1.2.2+ds1-2+deb10u5", rls:"DEB10"))) {
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
