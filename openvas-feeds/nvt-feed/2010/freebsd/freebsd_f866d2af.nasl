# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67993");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-3432");
  script_name("FreeBSD Ports: vim6, vim6+ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  vim6
   vim6+ruby

CVE-2008-3432
Heap-based buffer overflow in the mch_expand_wildcards function in
os_unix.c in Vim 6.2 and 6.3 allows user-assisted attackers to execute
arbitrary code via shell metacharacters in filenames, as demonstrated
by the netrw.v3 test case.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/07/15/4");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f866d2af-bbba-11df-8a8d-0008743bf21a.html");

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

bver = portver(pkg:"vim6");
if(!isnull(bver) && revcomp(a:bver, b:"6.2.429")>=0 && revcomp(a:bver, b:"6.3.62")<0) {
  txt += 'Package vim6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"vim6+ruby");
if(!isnull(bver) && revcomp(a:bver, b:"6.2.429")>=0 && revcomp(a:bver, b:"6.3.62")<0) {
  txt += 'Package vim6+ruby version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}