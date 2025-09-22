# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52218");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1030", "CVE-2004-1031", "CVE-2004-1032", "CVE-2004-1033");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: fcron");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: fcron

CVE-2004-1030
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to gain sensitive information by calling
fcronsighup with an arbitrary file, which reveals the contents of the
file that can not be parsed in an error message.

CVE-2004-1031
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to bypass access restrictions and load an arbitrary
configuration file by starting an suid process and pointing the
fcronsighup configuration file to a /proc entry that is owned by root
but modifiable by the user, such as /proc/self/cmdline or
/proc/self/environ.

CVE-2004-1032
fcronsighup in Fcron 2.0.1, 2.9.4, and possibly earlier versions
allows local users to delete arbitrary files or create arbitrary empty
files via a target filename with a large number of leading slash (/)
characters such that fcronsighup does not properly append the intended
fcrontab.sig to the resulting string.

CVE-2004-1033
Fcron 2.0.1, 2.9.4, and possibly earlier versions leak file
descriptors of open files, which allows local users to bypass access
restrictions and read fcron.allow and fcron.deny via the EDITOR
environment variable.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=157&type=vulnerabilities&flashstatus=false");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e480ccb2-6bc8-11d9-8dbe-000a95bc6fae.html");

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

bver = portver(pkg:"fcron");
if(!isnull(bver) && revcomp(a:bver, b:"2.9.5.1")<0) {
  txt += 'Package fcron version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}