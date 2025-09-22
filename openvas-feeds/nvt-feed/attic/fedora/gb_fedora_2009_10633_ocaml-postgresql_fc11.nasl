# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66257");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-2943");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-10633 (ocaml-postgresql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

  - New upstream version 1.12.3.  - This contains a SECURITY fix for:

CVE-2009-2943 ocaml-postgresql: Missing escape function (DSA-1909-1)
HOWEVER you are not protected until you change your code to  use the
new connection#escape_string method.

ChangeLog:

  * Fri Oct 16 2009 Richard W.M. Jones  - 1.12.3-1.fc11.2

  - Fix build process for new upstream tarball layout.

  * Fri Oct 16 2009 Richard W.M. Jones  - 1.12.3-1

  - New upstream version 1.12.3.

  - This contains a SECURITY fix for:

CVE-2009-2943 ocaml-postgresql: Missing escape function (DSA-1909-1)
HOWEVER you are not protected until you change your code to
use the new connection#escape_string method.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update ocaml-postgresql' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10633");
  script_tag(name:"summary", value:"The remote host is missing an update to ocaml-postgresql
announced via advisory FEDORA-2009-10633.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=529325");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
