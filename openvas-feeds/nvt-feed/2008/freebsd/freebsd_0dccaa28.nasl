# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61617");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-17 04:23:15 +0200 (Wed, 17 Sep 2008)");
  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", "CVE-2008-3144");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: python24");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  python24
   python25
   python23

CVE-2008-2315
Multiple integer overflows in Python 2.5.2 and earlier allow
context-dependent attackers to have an unknown impact via vectors
related to the (1) stringobject, (2) unicodeobject, (3) bufferobject,
(4) longobject, (5) tupleobject, (6) stropmodule, (7) gcmodule, and
(8) mmapmodule modules.
CVE-2008-2316
Integer overflow in _hashopenssl.c in the hashlib module in Python
2.5.2 and earlier might allow context-dependent attackers to defeat
cryptographic digests, related to 'partial hashlib hashing of data
exceeding 4GB.'
CVE-2008-3142
Multiple buffer overflows in Python 2.5.2 and earlier on 32bit
platforms allow context-dependent attackers to cause a denial of
service (crash) or have unspecified other impact via a long string
that leads to incorrect memory allocation during Unicode string
processing, related to the unicode_resize function and the
PyMem_RESIZE macro.
CVE-2008-3144
Multiple integer overflows in the PyOS_vsnprintf function in
Python/mysnprintf.c in Python 2.5.2 and earlier allow
context-dependent attackers to cause a denial of service (memory
corruption) or have unspecified other impact via crafted input to
string formatting operations.  NOTE: the handling of certain integer
values is also affected by related integer underflows and an
off-by-one error.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2620");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2588");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2589");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31305");
  script_xref(name:"URL", value:"http://mail.python.org/pipermail/python-checkins/2008-July/072276.html");
  script_xref(name:"URL", value:"http://mail.python.org/pipermail/python-checkins/2008-July/072174.html");
  script_xref(name:"URL", value:"http://mail.python.org/pipermail/python-checkins/2008-June/070481.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0dccaa28-7f3c-11dd-8de5-0030843d3802.html");

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

bver = portver(pkg:"python24");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5_2")<0) {
  txt += 'Package python24 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"python25");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.2_3")<0) {
  txt += 'Package python25 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"python23");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}