# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61802");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
  script_cve_id("CVE-2007-6243", "CVE-2008-3873", "CVE-2007-4324", "CVE-2008-4401", "CVE-2008-4503");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: linux-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-flashplugin

CVE-2007-6243
Adobe Flash Player 9.x up to 9.0.48.0, 8.x up to 8.0.35.0, and 7.x up
to 7.0.70.0 does not sufficiently restrict the interpretation and
usage of cross-domain policy files, which makes it easier for remote
attackers to conduct cross-domain and cross-site scripting (XSS)
attacks.

CVE-2008-3873
The System.setClipboard method in ActionScript in Adobe Flash Player
9.0.124.0 and earlier allows remote attackers to populate the
clipboard with a URL that is difficult to delete and does not require
user interaction to populate the clipboard, as exploited in the wild
in August 2008.

CVE-2007-4324
ActionScript 3 (AS3) in Adobe Flash Player 9.0.47.0, and other
versions and other 9.0.124.0 and earlier versions, allows remote
attackers to bypass the Security Sandbox Model, obtain sensitive
information, and port scan arbitrary hosts via a Flash (SWF) movie
that specifies a connection to make, then uses timing discrepancies
from the SecurityErrorEvent error to determine whether a port is open
or not.  NOTE: 9.0.115.0 introduces support for a workaround, but does
not fix the vulnerability.

CVE-2008-4401
ActionScript in Adobe Flash Player 9.0.124.0 and earlier does not
require user interaction in conjunction with (1) the
FileReference.browse operation in the FileReference upload API or (2)
the FileReference.download operation in the FileReference download
API, which allows remote attackers to create a browse dialog box, and
possibly have unspecified other impact, via an SWF file.

CVE-2008-4503
The Settings Manager in Adobe Flash Player 9.0.124.0 and earlier
allows remote attackers to cause victims to unknowingly click on a
link or dialog via access control dialogs disguised as normal
graphical elements, as demonstrated by hijacking the camera or
microphone, and related to 'clickjacking.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-18.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/78f456fd-9c87-11dd-a55e-00163e000016.html");

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

bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r124_1")<=0) {
  txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}