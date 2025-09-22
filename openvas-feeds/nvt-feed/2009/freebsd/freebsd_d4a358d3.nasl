# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63165");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
  script_cve_id("CVE-2008-5027");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: nagios");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  nagios
   nagios2

CVE-2008-5027
The Nagios process in (1) Nagios before 3.0.5 and (2) op5 Monitor
before 4.0.1 allows remote authenticated users to bypass authorization
checks, and trigger execution of arbitrary programs by this process,
via an (a) custom form or a (b) browser addon.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32156");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-698-1");
  script_xref(name:"URL", value:"http://www.nagios.org/development/history/nagios-3x.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/d4a358d3-e09a-11dd-a765-0030843d3802.html");

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

bver = portver(pkg:"nagios");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.5")<0) {
  txt += 'Package nagios version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"nagios2");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package nagios2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}