# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63327");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
  script_cve_id("CVE-2009-0413");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 9 FEDORA-2009-1256 (roundcubemail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Upgrade to 0.2 stable.

The following security fix is included as well:
Common Vulnerabilities and Exposures assigned an identifier
CVE-2009-0413 to  the following vulnerability:

Cross-site scripting (XSS) vulnerability in RoundCube Webmail
(roundcubemail) 0.2 stable allows remote attackers to inject
arbitrary web script or HTML via the background attribute
embedded in an HTML e-mail message.

ChangeLog:

  * Wed Feb  4 2009 Jon Ciesla  = 0.2-7.stable

  - Patch for CVE-2009-0413, BZ 484052.

  * Mon Jan  5 2009 Jon Ciesla  = 0.2-6.stable

  - New upstream.

  - Dropped two most recent patches, applied upstream.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update roundcubemail' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1256");
  script_tag(name:"summary", value:"The remote host is missing an update to roundcubemail
announced via advisory FEDORA-2009-1256.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=484052");
  script_xref(name:"URL", value:"http://trac.roundcube.net/changeset/2245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33372");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33622");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48129");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
