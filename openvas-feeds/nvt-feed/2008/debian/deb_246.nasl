# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53322");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0042", "CVE-2003-0043", "CVE-2003-0044");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 246-1 (tomcat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20246-1");
  script_tag(name:"insight", value:"The developers of tomcat discovered several problems in tomcat version
3.x.  The Common Vulnerabilities and Exposures project identifies the
following problems:

. CVE-2003-0042: A maliciously crafted request could return a
directory listing even when an index.html, index.jsp, or other
welcome file is present.  File contents can be returned as well.

. CVE-2003-0043: A malicious web application could read the contents
of some files outside the web application via its web.xml file in
spite of the presence of a security manager.  The content of files
that can be read as part of an XML document would be accessible.

. CVE-2003-0044: A cross-site scripting vulnerability was discovered
in the included sample web application that allows remote attackers
to execute arbitrary script code.

For the stable distribution (woody) this problem has been fixed in
version 3.3a-4.1.

The old stable distribution (potato) does not contain tomcat packages.

For the unstable distribution (sid) this problem has been fixed in
version 3.3.1a-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your tomcat package.");
  script_tag(name:"summary", value:"The remote host is missing an update to tomcat
announced via advisory DSA 246-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tomcat", ver:"3.3a-4woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-jk", ver:"3.3a-4woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
