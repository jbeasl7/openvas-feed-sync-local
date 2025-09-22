# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66263");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-3384", "CVE-2009-2816");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 12 FEDORA-2009-11487 (qt)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

A security flaw was found in the WebKit's Cross-Origin Resource Sharing (CORS)
implementation.    Multiple security flaws (integer underflow, invalid pointer
dereference, buffer underflow and a denial of service) were found in the way
WebKit's FTP parser used to process remote FTP directory listings.

ChangeLog:

  * Thu Nov 12 2009 Jaroslav Reznik  - 4.5.3-9

  - CVE-2009-3384 - WebKit, ftp listing handling (#525788)

  - CVE-2009-2816 - WebKit, MITM Cross-Origin Resource Sharing (#525789)

  * Sun Nov  8 2009 Rex Dieter  - 4.5.3-8

  - -x11: Requires: %{name}-sqlite(ppc-32)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update qt' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11487");
  script_tag(name:"summary", value:"The remote host is missing an update to qt
announced via advisory FEDORA-2009-11487.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=525788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=525789");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
