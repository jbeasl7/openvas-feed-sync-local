# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63221");
  script_cve_id("CVE-2009-0135", "CVE-2009-0136");
  script_tag(name:"creation_date", value:"2009-01-20 21:42:09 +0000 (Tue, 20 Jan 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1706-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1706-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1706-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1706");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'amarok' package(s) announced via the DSA-1706-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tobias Klein discovered that integer overflows in the code the Amarok media player uses to parse Audible files may lead to the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 1.4.4-4etch1. Updated packages for sparc and arm will be provided later.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 1.4.10-2.

We recommend that you upgrade your amarok packages.");

  script_tag(name:"affected", value:"'amarok' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"amarok", ver:"1.4.4-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"amarok-engines", ver:"1.4.4-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"amarok-xine", ver:"1.4.4-4etch1", rls:"DEB4"))) {
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
