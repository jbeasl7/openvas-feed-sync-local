# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840240");
  script_cve_id("CVE-2006-7232", "CVE-2007-2692", "CVE-2007-6303", "CVE-2008-0226", "CVE-2008-0227");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-588-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-588-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-588-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/209699");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0' package(s) announced via the USN-588-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-588-1 fixed vulnerabilities in MySQL. In fixing CVE-2007-2692 for
Ubuntu 6.06, additional improvements were made to make privilege checks
more restictive. As a result, an upstream bug was exposed which could
cause operations on tables or views in a different database to fail. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Masaaki Hirose discovered that MySQL could be made to dereference
 a NULL pointer. An authenticated user could cause a denial of service
 (application crash) via an EXPLAIN SELECT FROM on the INFORMATION_SCHEMA
 table. This issue only affects Ubuntu 6.06 and 6.10. (CVE-2006-7232)

 Alexander Nozdrin discovered that MySQL did not restore database access
 privileges when returning from SQL SECURITY INVOKER stored routines. An
 authenticated user could exploit this to gain privileges. This issue
 does not affect Ubuntu 7.10. (CVE-2007-2692)

 Martin Friebe discovered that MySQL did not properly update the DEFINER
 value of an altered view. An authenticated user could use CREATE SQL
 SECURITY DEFINER VIEW and ALTER VIEW statements to gain privileges.
 (CVE-2007-6303)

 Luigi Auriemma discovered that yaSSL as included in MySQL did not
 properly validate its input. A remote attacker could send crafted
 requests and cause a denial of service or possibly execute arbitrary
 code. This issue did not affect Ubuntu 6.06 in the default installation.
 (CVE-2008-0226, CVE-2008-0227)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06.9", rls:"UBUNTU6.06 LTS"))) {
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
