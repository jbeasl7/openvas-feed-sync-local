# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840117");
  script_cve_id("CVE-2007-2444");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-460-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU7\.04");

  script_xref(name:"Advisory-ID", value:"USN-460-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-460-2");
  script_xref(name:"URL", value:"http://bugs.debian.org/424629");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-460-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-460-1 fixed several vulnerabilities in Samba. The upstream changes
for CVE-2007-2444 had an unexpected side-effect in Feisty. Shares
configured with the 'force group' option no longer behaved correctly.
This update corrects the problem. We apologize for the inconvenience.

Original advisory details:

 Paul Griffith and Andrew Hogue discovered that Samba did not fully drop
 root privileges while translating SIDs. A remote authenticated user
 could issue SMB operations during a small window of opportunity and gain
 root privileges. (CVE-2007-2444)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 7.04.");

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

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.24-2ubuntu1.2", rls:"UBUNTU7.04"))) {
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
