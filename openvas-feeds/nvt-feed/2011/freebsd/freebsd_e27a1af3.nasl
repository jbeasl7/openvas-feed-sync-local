# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69755");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_name("FreeBSD Ports: subversion");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  subversion
   subversion-freebsd

CVE-2011-1752
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion before 1.6.17, allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via a
request for a baselined WebDAV resource, as exploited in the wild in
May 2011.
CVE-2011-1783
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion 1.5.x and 1.6.x before 1.6.17, when the SVNPathAuthz
short_circuit option is enabled, allows remote attackers to cause a
denial of service (infinite loop and memory consumption) in
opportunistic circumstances by requesting data.
CVE-2011-1921
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion 1.5.x and 1.6.x before 1.6.17, when the SVNPathAuthz
short_circuit option is disabled, does not properly enforce
permissions for files that had been publicly readable in the past,
which allows remote attackers to obtain sensitive information via a
replay REPORT operation.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.17")<0) {
  txt += 'Package subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"subversion-freebsd");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.17")<0) {
  txt += 'Package subversion-freebsd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}