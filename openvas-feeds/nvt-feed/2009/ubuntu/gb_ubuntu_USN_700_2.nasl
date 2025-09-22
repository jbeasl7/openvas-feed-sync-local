# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63235");
  script_cve_id("CVE-2007-4829", "CVE-2008-1927", "CVE-2008-5302", "CVE-2008-5303");
  script_tag(name:"creation_date", value:"2009-01-20 21:42:09 +0000 (Tue, 20 Jan 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-700-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-700-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-700-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/315991");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-700-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-700-1 fixed vulnerabilities in Perl. Due to problems with the Ubuntu
8.04 build, some Perl .ph files were missing from the resulting update.
This update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 Jonathan Smith discovered that the Archive::Tar Perl module did not
 correctly handle symlinks when extracting archives. If a user or
 automated system were tricked into opening a specially crafted tar file,
 a remote attacker could over-write arbitrary files. (CVE-2007-4829)

 Tavis Ormandy and Will Drewry discovered that Perl did not correctly
 handle certain utf8 characters in regular expressions. If a user or
 automated system were tricked into using a specially crafted expression,
 a remote attacker could crash the application, leading to a denial
 of service. Ubuntu 8.10 was not affected by this issue. (CVE-2008-1927)

 A race condition was discovered in the File::Path Perl module's rmtree
 function. If a local attacker successfully raced another user's call
 of rmtree, they could create arbitrary setuid binaries. Ubuntu 6.06
 and 8.10 were not affected by this issue. (CVE-2008-5302)

 A race condition was discovered in the File::Path Perl module's rmtree
 function. If a local attacker successfully raced another user's call of
 rmtree, they could delete arbitrary files. Ubuntu 6.06 was not affected
 by this issue. (CVE-2008-5303)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 8.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.8.8-12ubuntu0.4", rls:"UBUNTU8.04 LTS"))) {
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
