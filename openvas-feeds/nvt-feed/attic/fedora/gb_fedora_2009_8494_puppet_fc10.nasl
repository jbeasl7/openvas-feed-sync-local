# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64852");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-8494 (puppet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes a number of bugs in both the packaging and upstream source.
See the package changelog and bug reports for complete details.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update puppet' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8494");
  script_tag(name:"summary", value:"The remote host is missing an update to puppet
announced via advisory FEDORA-2009-8494.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=475201");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480600");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495096");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=501577");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515728");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
