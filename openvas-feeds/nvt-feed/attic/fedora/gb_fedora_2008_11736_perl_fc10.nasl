# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63089");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-02 18:22:54 +0100 (Fri, 02 Jan 2009)");
  script_cve_id("CVE-2007-4829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2008-11736 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

CVE-2007-4829 perl-Archive-Tar directory traversal flaws. Update of Pod::Simple
with better html support.

ChangeLog:

  * Mon Dec 22 2008 Marcela Maláová  - 4:5.10.0-52

  - add missing XHTML.pm into Pod::Simple

  - 295021 CVE-2007-4829 perl-Archive-Tar directory traversal flaws

  - add another source for binary files, which test untaring links

  * Fri Nov 28 2008 Tom spot Callaway  - 4:5.10.0-51

  - to fix Fedora bz 473223, which is really perl bug #54186
we apply Changes 33640, 33881, 33896, 33897

  * Mon Nov 24 2008 Marcela Maláová  - 4:5.10.0-50

  - change summary according to RFC fix summary discussion at fedora-devel :)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2008-11736");
  script_tag(name:"summary", value:"The remote host is missing an update to perl
announced via advisory FEDORA-2008-11736.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=295021");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
