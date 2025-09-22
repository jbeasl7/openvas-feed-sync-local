# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52252");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0021", "CVE-2005-0022");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("exim -- two buffer overflow vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  exim, exim-ldap, exim-ldap2, exim-mysql, exim-postgresql, exim-sa-exim

CVE-2005-0021
Multiple buffer overflows in Exim before 4.43 may allow attackers to
execute arbitrary code via (1) an IPv6 address with more than 8
components, as demonstrated using the -be command line option, which
triggers an overflow in the host_aton function, or (2) the -bh command
line option or dnsdb PTR lookup, which triggers an overflow in the
dns_build_reverse function.

CVE-2005-0022
Buffer overflow in the spa_base64_to_bits function in Exim before
4.43, as originally obtained from Samba code, and as called by the
auth_spa_client function, may allow attackers to execute arbitrary
code during SPA authentication.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.exim.org/mail-archives/exim-announce/2005/msg00000.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12268");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110573573800377");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ca9ce879-5ebb-11d9-a01c-0050569f0001.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-ldap");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim-ldap version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-ldap2");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim-ldap2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"exim-sa-exim");
if(!isnull(bver) && revcomp(a:bver, b:"4.43+28_1")<0) {
  txt += 'Package exim-sa-exim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}