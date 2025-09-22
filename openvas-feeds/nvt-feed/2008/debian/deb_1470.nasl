# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60213");
  script_cve_id("CVE-2007-6018");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1470-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1470-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1470");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horde3' package(s) announced via the DSA-1470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar discovered that the HTML filter of the Horde web application framework performed insufficient input sanitising, which may lead to the deletion of emails if a user is tricked into viewing a malformed email inside the Imp client.

This update also provides backported bugfixes to the cross-site scripting filter and the user management API from the latest Horde release 3.1.6.

The old stable distribution (sarge) is not affected. An update to Etch is recommended, though.

For the stable distribution (etch), this problem has been fixed in version 3.1.3-4etch2.

We recommend that you upgrade your horde3 package.");

  script_tag(name:"affected", value:"'horde3' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"horde3", ver:"3.1.3-4etch2", rls:"DEB4"))) {
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
