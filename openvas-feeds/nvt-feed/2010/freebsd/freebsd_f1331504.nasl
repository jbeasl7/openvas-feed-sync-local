# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67714");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-22 17:43:43 +0200 (Thu, 22 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-1204", "CVE-2010-0180");
  script_name("FreeBSD Ports: bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: bugzilla

CVE-2010-1204
Search.pm in Bugzilla 2.17.1 through 3.2.6, 3.3.1 through 3.4.6, 3.5.1
through 3.6, and 3.7 allows remote attackers to obtain potentially
sensitive time-tracking information via a crafted search URL, related
to a 'boolean chart search.'

CVE-2010-0180
Install/Filesystem.pm in Bugzilla 3.5.1 through 3.6 and 3.7, when
use_suexec is enabled, uses world-readable permissions for the
localconfig files, which allows local users to read sensitive
configuration fields, as demonstrated by the database password field
and the site_wide_secret field.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=309952");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=561797");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f1331504-8849-11df-89b8-00151735203a.html");

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

bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"2.17.1")>0 && revcomp(a:bver, b:"3.6.1")<0) {
  txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}