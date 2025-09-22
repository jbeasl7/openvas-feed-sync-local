# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893283");
  script_cve_id("CVE-2022-48279", "CVE-2023-24021");
  script_tag(name:"creation_date", value:"2023-01-27 02:00:08 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:14:35 +0000 (Mon, 06 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3283-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3283-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3283-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/modsecurity-apache");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'modsecurity-apache' package(s) announced via the DLA-3283-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in modsecurity-apache, open source, cross platform web application firewall (WAF) engine for Apache which allows remote attackers to bypass the applications firewall and other unspecified impact.

CVE-2022-48279

In ModSecurity before 2.9.6 and 3.x before 3.0.8, HTTP multipart requests were incorrectly parsed and could bypass the Web Application Firewall. NOTE: this is related to CVE-2022-39956 but can be considered independent changes to the ModSecurity (C language) codebase.

CVE-2023-24021

Incorrect handling of null-bytes in file uploads in ModSecurity before 2.9.7 may allow for Web Application Firewall bypasses and buffer overflows on the Web Application Firewall when executing rules reading the FILES_TMP_CONTENT collection.

For Debian 10 buster, these problems have been fixed in version 2.9.3-1+deb10u2.

We recommend that you upgrade your modsecurity-apache packages.

For the detailed security status of modsecurity-apache please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'modsecurity-apache' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-security2", ver:"2.9.3-1+deb10u2", rls:"DEB10"))) {
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
