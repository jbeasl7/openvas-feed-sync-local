# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58836");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: gd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gd");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.libgd.org/ReleaseNote020035");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2007/2336");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=89");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=94");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=70");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=87");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=92");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=74");
  script_xref(name:"URL", value:"http://bugs.libgd.org/?do=details&task_id=48");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=40578");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6e099997-25d8-11dc-878b-000c29c5647f.html");

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

bver = portver(pkg:"gd");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.35,1")<0) {
  txt += 'Package gd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}