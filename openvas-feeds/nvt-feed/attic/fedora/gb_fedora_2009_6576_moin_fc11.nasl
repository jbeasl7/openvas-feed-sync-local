# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64243");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-6576 (moin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This package updates Moin to 1.8.4. This package includes a security fix for a hierarchical ACL
vulnerability (hierarchical is not the default ACL mode).

ChangeLog:

  * Sat Jun 13 2009 Ville-Pekka Vainio  1.8.4-1

  - Update to 1.8.4

  - Includes a security fix for hierarchical ACL (not the default mode).

  - Drop previous security patches, those are not needed anymore.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6576");
  script_tag(name:"summary", value:"The remote host is missing an update to moin
announced via advisory FEDORA-2009-6576.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
