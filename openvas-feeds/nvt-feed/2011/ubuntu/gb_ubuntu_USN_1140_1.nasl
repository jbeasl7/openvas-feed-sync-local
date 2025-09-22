# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840672");
  script_cve_id("CVE-2009-0887", "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707");
  script_tag(name:"creation_date", value:"2011-06-06 14:56:27 +0000 (Mon, 06 Jun 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1140-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1140-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-1140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcus Granado discovered that PAM incorrectly handled configuration files
with non-ASCII usernames. A remote attacker could use this flaw to cause a
denial of service, or possibly obtain login access with a different users
username. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-0887)

It was discovered that the PAM pam_xauth, pam_env and pam_mail modules
incorrectly handled dropping privileges when performing operations. A local
attacker could use this flaw to read certain arbitrary files, and access
other sensitive information. (CVE-2010-3316, CVE-2010-3430, CVE-2010-3431,
CVE-2010-3435)

It was discovered that the PAM pam_namespace module incorrectly cleaned the
environment during execution of the namespace.init script. A local attacker
could use this flaw to possibly gain privileges. (CVE-2010-3853)

It was discovered that the PAM pam_xauth module incorrectly handled certain
failures. A local attacker could use this flaw to delete certain unintended
files. (CVE-2010-4706)

It was discovered that the PAM pam_xauth module incorrectly verified
certain file properties. A local attacker could use this flaw to cause a
denial of service. (CVE-2010-4707)");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.1-2ubuntu5.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.1-4ubuntu2.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.2-2ubuntu8.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"0.99.7.1-5ubuntu6.3", rls:"UBUNTU8.04 LTS"))) {
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
