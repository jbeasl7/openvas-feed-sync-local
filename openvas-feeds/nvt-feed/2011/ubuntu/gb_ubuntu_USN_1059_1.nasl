# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840583");
  script_cve_id("CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780");
  script_tag(name:"creation_date", value:"2011-02-11 12:26:17 +0000 (Fri, 11 Feb 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1059-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1059-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the USN-1059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ACL plugin in Dovecot would incorrectly
propagate ACLs to new mailboxes. A remote authenticated user could possibly
read new mailboxes that were created with the wrong ACL. (CVE-2010-3304)

It was discovered that the ACL plugin in Dovecot would incorrectly merge
ACLs in certain circumstances. A remote authenticated user could possibly
bypass intended access restrictions and gain access to mailboxes.
(CVE-2010-3706, CVE-2010-3707)

It was discovered that the ACL plugin in Dovecot would incorrectly grant
the admin permission to owners of certain mailboxes. A remote authenticated
user could possibly bypass intended access restrictions and gain access to
mailboxes. (CVE-2010-3779)

It was discovered that Dovecot incorrectly handled the simultaneous
disconnect of a large number of sessions. A remote authenticated user could
use this flaw to cause Dovecot to crash, resulting in a denial of service.
(CVE-2010-3780)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1:1.2.9-1ubuntu6.3", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1:1.2.12-1ubuntu8.1", rls:"UBUNTU10.10"))) {
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
