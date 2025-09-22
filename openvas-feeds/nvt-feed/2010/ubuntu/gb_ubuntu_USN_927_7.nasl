# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840466");
  script_tag(name:"creation_date", value:"2010-07-26 14:14:51 +0000 (Mon, 26 Jul 2010)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-927-7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.04");

  script_xref(name:"Advisory-ID", value:"USN-927-7");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-927-7");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/599920");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr' package(s) announced via the USN-927-7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-927-4 fixed vulnerabilities in NSS. This update provides the NSPR
needed to use the new NSS.

Original advisory details:

 Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
 protocols. If an attacker could perform a machine-in-the-middle attack at the
 start of a TLS connection, the attacker could inject arbitrary content at
 the beginning of the user's session. This update adds support for the new
 new renegotiation extension and will use it when the server supports it.");

  script_tag(name:"affected", value:"'nspr' package(s) on Ubuntu 9.04.");

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

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"4.8-0ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
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
