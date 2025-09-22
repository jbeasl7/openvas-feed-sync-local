# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64304");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1760");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-6760 (deluge)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Deluge 1.1.9 contains updated translations and fixes for a move torrent issue
(now only happens when the torrent has data downloaded), a folder renaming bug
(renaming a parent folder into multiple folders), and an issue with adding a
remote torrent in the WebUI.    This update also includes all upstream bug-fixes
and enhancements in versions 1.1.7 and 1.1.8 (which were skipped in this
package). In addition, the included copy
of rb_libtorrent has been updated to fix a potential directory traversal
vulnerability which would allow a remote attacker to create or overwrite
arbitrary files via a .. (dot dot) and partial relative pathname in a
specially-crafted torrent.

ChangeLog:

  * Wed Jun 17 2009 Peter Gordon  - 1.1.9-1

  - Update to new upstream bug-fix release (1.1.9), updates internal libtorrent
copy to fix CVE-2009-1760 (#505523).

  - Adds dependency on chardet for fixing lots of bugs with torrents
which are not encoded as UTF-8.

  - Add back the flags, in an optional -flags subpackage as per the new Flags
policy (Package_Maintainers_Flags_Policy on the wiki).

  - Add LICENSE and README to installed documentation.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update deluge' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6760");
  script_tag(name:"summary", value:"The remote host is missing an update to deluge
announced via advisory FEDORA-2009-6760.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505523");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
