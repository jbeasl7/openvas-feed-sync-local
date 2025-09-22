# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841943");
  script_cve_id("CVE-2014-3473", "CVE-2014-3474", "CVE-2014-3475", "CVE-2014-3594");
  script_tag(name:"creation_date", value:"2014-08-22 03:57:29 +0000 (Fri, 22 Aug 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2323-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2323-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'horizon' package(s) announced via the USN-2323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jason Hullinger discovered that OpenStack Horizon did not properly perform
input sanitization on Heat templates. If a user were tricked into using a
specially crafted Heat template, an attacker could conduct cross-site
scripting attacks. With cross-site scripting vulnerabilities, if a user
were tricked into viewing server output during a crafted server request, a
remote attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2014-3473)

Craig Lorentzen discovered that OpenStack Horizon did not properly perform
input sanitization when creating networks. If a user were tricked into
launching an image using the crafted network name, an attacker could
conduct cross-site scripting attacks. (CVE-2014-3474)

Michael Xin discovered that OpenStack Horizon did not properly perform
input sanitization when adding users. If an admin user were tricked into
viewing the users page containing a crafted email address, an attacker
could conduct cross-site scripting attacks. (CVE-2014-3475)

Dennis Felsch and Mario Heiderich discovered that OpenStack Horizon did not
properly perform input sanitization when creating host aggregates. If an
admin user were tricked into viewing the Host Aggregates page containing a
crafted availability zone name, an attacker could conduct cross-site
scripting attacks. (CVE-2014-3594)");

  script_tag(name:"affected", value:"'horizon' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openstack-dashboard", ver:"1:2014.1.2-0ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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
