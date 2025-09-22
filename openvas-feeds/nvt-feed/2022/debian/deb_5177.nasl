# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705177");
  script_cve_id("CVE-2022-24851", "CVE-2022-31084", "CVE-2022-31085", "CVE-2022-31086", "CVE-2022-31087", "CVE-2022-31088");
  script_tag(name:"creation_date", value:"2022-07-07 01:00:10 +0000 (Thu, 07 Jul 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 14:37:13 +0000 (Thu, 07 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5177-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5177-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5177");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ldap-account-manager");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldap-account-manager' package(s) announced via the DSA-5177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arseniy Sharoglazov discovered multiple security issues in LDAP Account Manager (LAM), a web frontend for managing accounts in an LDAP directory, which could result in information disclosure or unauthenticated remote code execution.

For the stable distribution (bullseye), these problems have been fixed in version 8.0.1-0+deb11u1.

We recommend that you upgrade your ldap-account-manager packages.

For the detailed security status of ldap-account-manager please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ldap-account-manager' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"ldap-account-manager", ver:"8.0.1-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ldap-account-manager-lamdaemon", ver:"8.0.1-0+deb11u1", rls:"DEB11"))) {
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
