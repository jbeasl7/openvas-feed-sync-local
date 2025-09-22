# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70752");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0022");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: tomcat

CVE-2012-0022
Apache Tomcat 5.5.x before 5.5.35, 6.x before 6.0.34, and 7.x before
7.0.23 uses an inefficient approach for handling parameters, which
allows remote attackers to cause a denial of service (CPU consumption)
via a request that contains many parameters and parameter values, a
different vulnerability than CVE-2011-4858.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.35");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.34");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.23");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/7f5ccb1d-439b-11e1-bc16-0023ae8e59f0.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"5.5.0")>0 && revcomp(a:bver, b:"5.5.35")<0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.34")<0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"7.0.0")>0 && revcomp(a:bver, b:"7.0.23")<0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}