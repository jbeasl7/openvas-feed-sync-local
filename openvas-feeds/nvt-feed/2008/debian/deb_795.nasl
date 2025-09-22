# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55234");
  script_cve_id("CVE-2005-2390");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-795-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-795-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-795-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-795");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd' package(s) announced via the DSA-795-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"infamous42md reported that proftpd suffers from two format string vulnerabilities. In the first, a user with the ability to create a directory could trigger the format string error if there is a proftpd shutdown message configured to use the '%C', '%R', or '%U' variables. In the second, the error is triggered if mod_sql is used to retrieve messages from a database and if format strings have been inserted into the database by a user with permission to do so.

The old stable distribution (woody) is not affected by these vulnerabilities.

For the stable distribution (sarge) this problem has been fixed in version 1.2.10-15sarge1. There was an error in the packages originally prepared for i386, which was corrected in 1.2.10-15sarge1.0.1 for i386.

For the unstable distribution (sid) this problem has been fixed in version 1.2.10-20.

We recommend that you upgrade your proftpd package.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"proftpd", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-common", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.2.10-15sarge1", rls:"DEB3.1"))) {
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
