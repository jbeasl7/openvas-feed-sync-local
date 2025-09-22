# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55116");
  script_cve_id("CVE-2005-2556", "CVE-2005-2557");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-778-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-778-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-778-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-778");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-778-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security related problems have been discovered in Mantis, a web-based bug tracking system. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2556

A remote attacker could supply a specially crafted URL to scan arbitrary ports on arbitrary hosts that may not be accessible otherwise.

CAN-2005-2557

A remote attacker was able to insert arbitrary HTML code in bug reports, hence, cross site scripting.

CAN-2005-3090

A remote attacker was able to insert arbitrary HTML code in bug reports, hence, cross site scripting.

The old stable distribution (woody) does not seem to be affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 0.19.2-4.

For the unstable distribution (sid) these problems have been fixed in version 0.19.2-4.

We recommend that you upgrade your mantis package.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mantis", ver:"0.19.2-4", rls:"DEB3.1"))) {
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
