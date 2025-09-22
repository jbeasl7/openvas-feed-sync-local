# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63777");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-2834 (krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update incorporates patches to fix potential read overflow and NULL pointer
dereferences in the implementation of the SPNEGO GSSAPI mechanism
(CVE-2009-0844, CVE-2009-0845), attempts to free an uninitialized pointer during
protocol parsing (CVE-2009-0846), and a bug in length validation during protocol
parsing (CVE-2009-0847).

ChangeLog:

  * Tue Apr  7 2009 Nalin Dahyabhai  1.6.3-16

  - add patches for read overflow and null pointer dereference in the
implementation of the SPNEGO mechanism (CVE-2009-0844, CVE-2009-0845)

  - add patch for attempt to free uninitialized pointer in libkrb5
(CVE-2009-0846)

  - add patch to fix length validation bug in libkrb5 (CVE-2009-0847)

  * Mon Apr  6 2009 Nalin Dahyabhai

  - pull in a couple of defuzzed patches from the F-10 version of this package,
dropping a redundant man page patch in the process");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update krb5' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2834");
  script_tag(name:"summary", value:"The remote host is missing an update to krb5
announced via advisory FEDORA-2009-2834.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490634");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491036");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491034");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
