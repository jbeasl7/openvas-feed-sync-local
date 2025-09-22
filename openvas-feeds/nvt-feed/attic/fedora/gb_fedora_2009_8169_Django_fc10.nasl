# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64548");
  script_cve_id("CVE-2009-2659");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-8169 (Django)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Django is a high-level Python Web framework that encourages rapid
development and a clean, pragmatic design. It focuses on automating as
much as possible and adhering to the DRY (Don't Repeat Yourself)
principle.

Update Information:

ChangeLog:

  * Wed Jul 29 2009 Steve 'Ashcrow' Milner  - 1.0.3-6

  - Attempted combined spec for F12/11/10 and EL5

  * Wed Jul 29 2009 Steve 'Ashcrow' Milner  - 1.0.3-4

  - Older builds must ghost django-admin.py[c, o]

  * Wed Jul 29 2009 Steve 'Ashcrow' Milner  - 1.0.3-3

  - Bump for tag issue.

  * Wed Jul 29 2009 Steve 'Ashcrow' Milner  - 1.0.3-2

  - Fix changelog.

  * Wed Jul 29 2009 Steve 'Ashcrow' Milner  - 1.0.3-1");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update Django' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8169");
  script_tag(name:"summary", value:"The remote host is missing an update to Django
announced via advisory FEDORA-2009-8169.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514581");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
