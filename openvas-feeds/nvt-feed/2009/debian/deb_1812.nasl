# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64185");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955");
  script_tag(name:"creation_date", value:"2009-06-09 17:38:29 +0000 (Tue, 09 Jun 2009)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1812-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1812-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1812");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apr-util' package(s) announced via the DSA-1812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apr-util, the Apache Portable Runtime Utility library, is used by Apache 2.x, Subversion, and other applications. Two denial of service vulnerabilities have been found in apr-util:

'kcope' discovered a flaw in the handling of internal XML entities in the apr_xml_* interface that can be exploited to use all available memory. This denial of service can be triggered remotely in the Apache mod_dav and mod_dav_svn modules. (No CVE id yet)

CVE-2009-0023

Matthew Palmer discovered an underflow flaw in the apr_strmatch_precompile function that can be exploited to cause a daemon crash. The vulnerability can be triggered (1) remotely in mod_dav_svn for Apache if the 'SVNMasterURI' directive is in use, (2) remotely in mod_apreq2 for Apache or other applications using libapreq2, or (3) locally in Apache by a crafted '.htaccess' file.

Other exploit paths in other applications using apr-util may exist.

If you use Apache, or if you use svnserve in standalone mode, you need to restart the services after you upgraded the libaprutil1 package.

The oldstable distribution (etch), these problems have been fixed in version 1.2.7+dfsg-2+etch2.

For the stable distribution (lenny), these problems have been fixed in version 1.2.12+dfsg-8+lenny2.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your apr-util packages.");

  script_tag(name:"affected", value:"'apr-util' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.7+dfsg-2+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbg", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.2.12+dfsg-8+lenny2", rls:"DEB5"))) {
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
