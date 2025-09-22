# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67648");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2451", "CVE-2010-2452");
  script_name("FreeBSD Ports: kvirc, kvirc-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  kvirc
   kvirc-devel

CVE-2010-2451
Multiple format string vulnerabilities in the DCC functionality in
KVIrc 3.4 and 4.0 have unspecified impact and remote attack vectors.

CVE-2010-2452
Directory traversal vulnerability in the DCC functionality in KVIrc
3.4 and 4.0 allows remote attackers to overwrite arbitrary files via
unknown vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://lists.omnikron.net/pipermail/kvirc/2010-May/000867.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8685d412-8468-11df-8d45-001d7d9eb79a.html");

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

bver = portver(pkg:"kvirc");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")<0) {
  txt += 'Package kvirc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kvirc-devel");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")<0) {
  txt += 'Package kvirc-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}