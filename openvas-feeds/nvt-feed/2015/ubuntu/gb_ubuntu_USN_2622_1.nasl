# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842231");
  script_cve_id("CVE-2012-1164", "CVE-2013-4449", "CVE-2015-1545");
  script_tag(name:"creation_date", value:"2015-06-09 09:09:41 +0000 (Tue, 09 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2622-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2622-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2622-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap' package(s) announced via the USN-2622-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenLDAP incorrectly handled certain search queries
that returned empty attributes. A remote attacker could use this issue to
cause OpenLDAP to assert, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS. (CVE-2012-1164)

Michael Vishchers discovered that OpenLDAP improperly counted references
when the rwm overlay was used. A remote attacker could use this issue to
cause OpenLDAP to crash, resulting in a denial of service. (CVE-2013-4449)

It was discovered that OpenLDAP incorrectly handled certain empty attribute
lists in search requests. A remote attacker could use this issue to cause
OpenLDAP to crash, resulting in a denial of service. (CVE-2015-1545)");

  script_tag(name:"affected", value:"'openldap' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.28-1.1ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.31-1+nmu2ubuntu8.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.31-1+nmu2ubuntu11.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.31-1+nmu2ubuntu12.1", rls:"UBUNTU15.04"))) {
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
