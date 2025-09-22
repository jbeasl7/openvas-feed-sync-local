# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61187");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-2712");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: vim, vim-lite, vim-ruby, vim6, vim6-ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  vim
   vim-lite
   vim-ruby
   vim6
   vim6-ruby

CVE-2008-2712
Vim 7.1.314, 6.4, and other versions allows user-assisted remote
attackers to execute arbitrary commands via Vim scripts that do not
properly sanitize inputs before invoking the execute or system
functions, as demonstrated using (1) filetype.vim, (2) zipplugin, (3)
xpm.vim, (4) gzip_vim, and (5) netrw.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/30866e6c-3c6d-11dd-98c9-00163e000016.html");

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

bver = portver(pkg:"vim");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
  txt += 'Package vim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
  txt += 'Package vim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim-lite");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
  txt += 'Package vim-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
  txt += 'Package vim-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim-ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
  txt += 'Package vim-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
  txt += 'Package vim-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim6");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
  txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
  txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim6-ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6")>0 && revcomp(a:bver, b:"6.4.10")<=0) {
  txt += 'Package vim6-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7")>0 && revcomp(a:bver, b:"7.1.315")<0) {
  txt += 'Package vim6-ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}