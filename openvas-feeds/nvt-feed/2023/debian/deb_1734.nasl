# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2009.1734");
  script_cve_id("CVE-2009-0368");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1734-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1734-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1734-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1734");
  script_xref(name:"URL", value:"http://www.opensc-project.org/security.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensc' package(s) announced via the DSA-1734-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"b.badrignans discovered that OpenSC, a set of smart card utilities, could stores private data on a smart card without proper access restrictions.

Only blank cards initialised with OpenSC are affected by this problem. This update only improves creating new private data objects, but cards already initialised with such private data objects need to be modified to repair the access control conditions on such cards. Instructions for a variety of situations can be found at the OpenSC web site: [link moved to references]

The oldstable distribution (etch) is not affected by this problem.

For the stable distribution (lenny), this problem has been fixed in version 0.11.4-5+lenny1.

For the unstable distribution (sid), this problem wil be fixed soon.

We recommend that you upgrade your opensc package and recreate any private data objects stored on your smart cards.");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2", ver:"0.11.4-5+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2-dbg", ver:"0.11.4-5+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2-dev", ver:"0.11.4-5+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-opensc", ver:"0.11.4-5+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.11.4-5+lenny1", rls:"DEB5"))) {
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
