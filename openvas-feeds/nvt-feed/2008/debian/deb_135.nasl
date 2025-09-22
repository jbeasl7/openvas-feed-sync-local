# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53851");
  script_cve_id("CVE-2002-0653");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:50:09 +0000 (Fri, 02 Feb 2024)");
  script_name("Debian Security Advisory DSA 135-1 (libapache-mod-ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20135-1");
  script_xref(name:"URL", value:"http://online.securityfocus.com/bid/5084");
  script_tag(name:"insight", value:"The libapache-mod-ssl package provides SSL capability to the apache
webserver.
Recently, a problem has been found in the handling of .htaccess files,
allowing arbitrary code execution as the web server user (regardless of
ExecCGI / suexec settings), DoS attacks (killing off apache children), and
allowing someone to take control of apache child processes - all through
specially crafted .htaccess files.
More information about this vulnerability can be found at the references.");

  script_tag(name:"solution", value:"This has been fixed in the libapache-mod-ssl_2.4.10-1.3.9-1potato2 package
(for potato), and the libapache-mod-ssl_2.8.9-2 package (for woody).
We recommend you upgrade as soon as possible.");
  script_tag(name:"summary", value:"The remote host is missing an update to libapache-mod-ssl
announced via advisory DSA 135-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.4.10-1.3.9-1potato2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.4.10-1.3.9-1potato2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.8.9-2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.8.9-2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
