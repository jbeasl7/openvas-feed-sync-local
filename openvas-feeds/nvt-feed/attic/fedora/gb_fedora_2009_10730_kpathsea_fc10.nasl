# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66260");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-1284");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-10730 (texlive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Fri Oct 23 2009 Jindrich Novy  2007-46

  - add missing dependency on kpathsea

  * Thu Oct 15 2009 Jindrich Novy  2007-45

  - make kpathsea not dependent on texlive

  - fix lacheck again (#451513)

  - fix dvips configuration (#467542)

  - update kpathsea description and summary (#519257)

  - use upstream patch to fix pool overflow CVE-2009-1284 (#492136)

  - don't complain if the pdvipsk hunks touching config.ps don't apply

  - avoid clashes with getline() from glibc

  - texlive-east-asian now requires texlive-texmf-east-asian (#487258)

  - do not attempt to remove old fonts via cron in /var/lib/texmf,
fonts are stored in ~/.texlive2007/texmf-var per-user
(#477833, #463975, #453468)

  - use correct paths in brp-* post install scriptlets (#468179)

  - fix build with gcc4.4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update texlive' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10730");
  script_tag(name:"summary", value:"The remote host is missing an update to texlive
announced via advisory FEDORA-2009-10730.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492136");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
