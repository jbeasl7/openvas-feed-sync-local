# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64200");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_tag(name:"creation_date", value:"2009-06-15 17:20:43 +0000 (Mon, 15 Jun 2009)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-786-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-786-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr-util' package(s) announced via the USN-786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthew Palmer discovered an underflow flaw in apr-util. An attacker could
cause a denial of service via application crash in Apache using a crafted
SVNMasterURI directive, .htaccess file, or when using mod_apreq2.
Applications using libapreq2 are also affected. (CVE-2009-0023)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a denial of service via memory
resource consumption by sending a crafted request to an Apache server
configured to use mod_dav or mod_dav_svn. (CVE-2009-1955)

C. Michael Pilato discovered an off-by-one buffer overflow in apr-util when
formatting certain strings. For big-endian machines (powerpc, hppa and
sparc in Ubuntu), a remote attacker could cause a denial of service or
information disclosure leak. All other architectures for Ubuntu are
not considered to be at risk. (CVE-2009-1956)");

  script_tag(name:"affected", value:"'apr-util' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-3ubuntu0.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-7ubuntu0.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-8ubuntu0.1", rls:"UBUNTU9.04"))) {
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
