# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68948");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0017");
  script_name("exim -- local privilege escalation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  exim, exim-ldap, exim-ldap2, exim-mysql, exim-postgresql, exim-sa-exim

CVE-2011-0017
The open_log function in log.c in Exim 4.72 and earlier does not check
the return value from (1) setuid or (2) setgid system calls, which
allows local users to append log data to arbitrary files via a symlink
attack.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_xref(name:"URL", value:"ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.74");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/44ccfab0-3564-11e0-8e81-0022190034c0.html");

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

bver = portver(pkg:"exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-ldap");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim-ldap version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-ldap2");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim-ldap2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-sa-exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.74")<0) {
  txt += 'Package exim-sa-exim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}