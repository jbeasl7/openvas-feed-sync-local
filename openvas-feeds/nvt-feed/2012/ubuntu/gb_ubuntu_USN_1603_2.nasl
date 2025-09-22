# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841203");
  script_cve_id("CVE-2012-4466", "CVE-2012-4481");
  script_tag(name:"creation_date", value:"2012-10-31 12:01:35 +0000 (Wed, 31 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1603-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");

  script_xref(name:"Advisory-ID", value:"USN-1603-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1603-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.8' package(s) announced via the USN-1603-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1603-1 fixed vulnerabilities in Ruby. This update provides the
corresponding updates for Ubuntu 12.10.

Original advisory details:

 Shugo Maedo and Vit Ondruch discovered that Ruby incorrectly allowed untainted
 strings to be modified in protective safe levels. An attacker could use this
 flaw to bypass intended access restrictions. (CVE-2012-4466, CVE-2012-4481)");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Ubuntu 12.10.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-4ubuntu0.1", rls:"UBUNTU12.10"))) {
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
