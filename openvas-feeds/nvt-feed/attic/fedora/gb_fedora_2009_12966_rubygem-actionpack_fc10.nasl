# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66496");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-4214", "CVE-2009-3009", "CVE-2008-5189");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-12966 (rubygem-actionpack)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Two security issues are found on activepack shipped on Fedora 10.  One bug is
that there is a weakness in the strip_tags function in ruby on rails (bug
542786, CVE-2009-4214). Another one is a possibility to circumvent protection
against cross-site request forgery (CSRF) attacks (bug 544329).

ChangeLog:

  * Mon Dec  7 2009 Mamoru Tasaka  - 2.1.1-5

  - Fix for potential CSRF protection circumvention (bug 544329)

  - Fix for XSS weakness in strip_tags (bug 542786)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update rubygem-actionpack' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12966");
  script_tag(name:"summary", value:"The remote host is missing an update to rubygem-actionpack
announced via advisory FEDORA-2009-12966.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=542786");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=544329");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
