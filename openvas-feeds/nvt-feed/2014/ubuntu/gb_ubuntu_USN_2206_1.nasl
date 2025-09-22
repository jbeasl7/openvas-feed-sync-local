# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841819");
  script_cve_id("CVE-2014-0157");
  script_tag(name:"creation_date", value:"2014-05-12 03:43:36 +0000 (Mon, 12 May 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2206-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  script_xref(name:"Advisory-ID", value:"USN-2206-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2206-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'horizon' package(s) announced via the USN-2206-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cristian Fiorentino discovered that OpenStack Horizon did not properly
perform input sanitization for Heat templates. If a user were tricked into
using a specially crafted Heat template, an attacker could conduct
cross-site scripting attacks. With cross-site scripting vulnerabilities, if
a user were tricked into viewing server output during a crafted server
request, a remote attacker could exploit this to modify the contents, or
steal confidential data, within the same domain.");

  script_tag(name:"affected", value:"'horizon' package(s) on Ubuntu 13.10.");

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

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openstack-dashboard", ver:"1:2013.2.3-0ubuntu1.1", rls:"UBUNTU13.10"))) {
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
