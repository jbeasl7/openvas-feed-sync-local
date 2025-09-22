# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840635");
  script_cve_id("CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0079", "CVE-2011-0081", "CVE-2011-1202");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1121-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1121-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Boris Zbarsky, Gary Kwong, Jesse Ruderman, Michael Wu, and Ted Mielczarek
discovered multiple memory vulnerabilities. An attacker could exploit these
to possibly run arbitrary code as the user running Firefox. (CVE-2011-0079)

It was discovered that there was a vulnerability in the memory handling of
certain types of content. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0081)

It was discovered that Firefox incorrectly handled certain JavaScript
requests. An attacker could exploit this to possibly run arbitrary code as
the user running Firefox. (CVE-2011-0069)

Ian Beer discovered a vulnerability in the memory handling of a certain
types of documents. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0070)

Chris Evans discovered a vulnerability in Firefox's XSLT generate-id()
function. An attacker could possibly use this vulnerability to make other
attacks more reliable. (CVE-2011-1202)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"4.0.1+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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
