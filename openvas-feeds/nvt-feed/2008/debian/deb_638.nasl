# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53473");
  script_cve_id("CVE-2004-0560", "CVE-2004-0561");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-638-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-638-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-638");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gopher' package(s) announced via the DSA-638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'jaguar' has discovered two security relevant problems in gopherd, the Gopher server in Debian which is part of the gopher package. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2004-0560

An integer overflow can happen when posting content of a specially calculated size.

CAN-2004-0561

A format string vulnerability has been found in the log routine.

For the stable distribution (woody) these problems have been fixed in version 3.0.3woody2.

The unstable distribution (sid) does not contain a gopherd package. It has been replaced by Pygopherd.

We recommend that you upgrade your gopherd package.");

  script_tag(name:"affected", value:"'gopher' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gopher", ver:"3.0.3woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gopherd", ver:"3.0.3woody2", rls:"DEB3.0"))) {
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
