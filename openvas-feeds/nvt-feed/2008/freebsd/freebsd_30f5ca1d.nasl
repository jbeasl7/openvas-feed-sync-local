# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60021");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-6227");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: qemu, qemu-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  qemu
   qemu-devel

CVE-2007-6227
QEMU 0.9.0 allows local users of a Windows XP SP2 guest operating
system to overwrite the TranslationBlock (code_gen_buffer) buffer, and
probably have unspecified other impacts related to an 'overflow, ' via
certain Windows executable programs, as demonstrated by qemu-dos.com.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/484429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26666");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/30f5ca1d-a90b-11dc-bf13-0211060005df.html");

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

bver = portver(pkg:"qemu");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0_4")<0) {
  txt += 'Package qemu version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0s.20070101*")>=0 && revcomp(a:bver, b:"0.9.0s.20070802_1")<0) {
  txt += 'Package qemu version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"qemu-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0_4")<0) {
  txt += 'Package qemu-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.0s.20070101*")>=0 && revcomp(a:bver, b:"0.9.0s.20070802_1")<0) {
  txt += 'Package qemu-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}