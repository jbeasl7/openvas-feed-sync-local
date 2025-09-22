# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64299");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1384");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-6255 (pam_krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This updates the pam_krb5 package from version 2.3.2 to 2.3.5, fixing
CVE-2009-1384: in certain configurations, the password prompt could vary
depending on whether or not the user account was known to the system or the KDC.
It also fixes a bug which prevented password change attempts from working if the
KDC denied requests for password-changing credentials with settings which would
be used for login credentials.

ChangeLog:

  * Tue May 26 2009 Nalin Dahyabhai  - 2.3.5-1

  - catch the case where we pass a NULL initial password into libkrb5 and
it uses our callback to ask us for the password for the user using a
principal name, and reject that (#502602)

  - always prompt for a password unless we were told not to (#502602,
CVE-2009-1384)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update pam_krb5' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6255");
  script_tag(name:"summary", value:"The remote host is missing an update to pam_krb5
announced via advisory FEDORA-2009-6255.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502602");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
