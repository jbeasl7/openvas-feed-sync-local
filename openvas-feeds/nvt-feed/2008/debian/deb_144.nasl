# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53580");
  script_cve_id("CVE-2002-0818");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-144)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-144");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-144");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-144");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wwwoffle' package(s) announced via the DSA-144 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A problem with wwwoffle has been discovered. The web proxy didn't handle input data with negative Content-Length settings properly which causes the processing child to crash. It is at this time not obvious how this can lead to an exploitable vulnerability, however, it's better to be safe than sorry, so here's an update.

Additionally, in the woody version empty passwords will be treated as wrong when trying to authenticate. In the woody version we also replaced CanonicaliseHost() with the latest routine from 2.7d, offered by upstream. This stops bad IPv6 format IP addresses in URLs from causing problems (memory overwriting, potential exploits).

This problem has been fixed in version 2.5c-10.4 for the old stable distribution (potato), in version 2.7a-1.2 for the current stable distribution (woody) and in version 2.7d-1 for the unstable distribution (sid).

We recommend that you upgrade your wwwoffle packages.");

  script_tag(name:"affected", value:"'wwwoffle' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"wwwoffle", ver:"2.7a-1.2", rls:"DEB3.0"))) {
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
