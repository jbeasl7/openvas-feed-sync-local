# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52133");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1080");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: jdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  jdk, linux-ibm-jdk, linux-sun-jdk, linux-blackdown-jdk, diablo-jdk, linux-jdk

CVE-2005-1080
Directory traversal vulnerability in the Java Archive Tool (Jar)
utility in J2SE SDK 1.4.2, 1.5 allows remote attackersto write
arbitrary files via a .. (dot dot) in filenames in a .jar file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5IP0C0AFGW.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/14902/");
  script_xref(name:"URL", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=111331593310508");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/18e5428f-ae7c-11d9-837d-000e0c2e438a.html");

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

bver = portver(pkg:"jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2p8")<=0) {
  txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.5")>=0 && revcomp(a:bver, b:"1.5.0p1_1")<=0) {
  txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-ibm-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2_1")<=0) {
  txt += 'Package linux-ibm-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-sun-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2.08_1")<=0) {
  txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.5")>=0 && revcomp(a:bver, b:"1.5.2.02,2")<=0) {
  txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-blackdown-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.2_2")<=0) {
  txt += 'Package linux-blackdown-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"diablo-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
  txt += 'Package diablo-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}