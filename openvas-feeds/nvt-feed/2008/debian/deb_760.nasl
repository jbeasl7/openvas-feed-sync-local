# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54370");
  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1916");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:01:37 +0000 (Fri, 26 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-760-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-760-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-760");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ekg' package(s) announced via the DSA-760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ekg, a console Gadu Gadu client, an instant messaging program. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2005-1850

Marcin Owsiany and Wojtek Kaniewski discovered insecure temporary file creation in contributed scripts.

CAN-2005-1851

Marcin Owsiany and Wojtek Kaniewski discovered potential shell command injection in a contributed script.

CAN-2005-1916

Eric Romang discovered insecure temporary file creation and arbitrary command execution in a contributed script that can be exploited by a local attacker.

The old stable distribution (woody) does not contain an ekg package.

For the stable distribution (sarge) these problems have been fixed in version 1.5+20050411-4.

For the unstable distribution (sid) these problems have been fixed in version 1.5+20050712+1.6rc2-1.

We recommend that you upgrade your ekg package.");

  script_tag(name:"affected", value:"'ekg' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ekg", ver:"1:1.5+20050411-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1:1.5+20050411-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1:1.5+20050411-4", rls:"DEB3.1"))) {
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
