# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702892");
  script_cve_id("CVE-2001-1593", "CVE-2014-0466");
  script_tag(name:"creation_date", value:"2014-03-30 22:00:00 +0000 (Sun, 30 Mar 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2892-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2892-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2892");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'a2ps' package(s) announced via the DSA-2892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in a2ps, an Anything to PostScript converter and pretty-printer. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2001-1593

The spy_user function which is called when a2ps is invoked with the --debug flag insecurely used temporary files.

CVE-2014-0466

Brian M. Carlson reported that a2ps's fixps script does not invoke gs with the -dSAFER option. Consequently executing fixps on a malicious PostScript file could result in files being deleted or arbitrary commands being executed with the privileges of the user running fixps.

For the oldstable distribution (squeeze), these problems have been fixed in version 1:4.14-1.1+deb6u1.

For the stable distribution (wheezy), these problems have been fixed in version 1:4.14-1.1+deb7u1.

For the testing distribution (jessie) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your a2ps packages.");

  script_tag(name:"affected", value:"'a2ps' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"a2ps", ver:"1:4.14-1.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"a2ps", ver:"1:4.14-1.1+deb7u1", rls:"DEB7"))) {
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
