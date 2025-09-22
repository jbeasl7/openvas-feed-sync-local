# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67356");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0825");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: movemail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following packages are affected:

  movemail
   emacs
   xemacs
   xemacs-devel
   xemacs-mule
   zh-xemacs-mule
   ja-xemacs-mule-canna
   xemacs-devel-mule
   xemacs-devel-mule-xft

CVE-2010-0825
lib-src/movemail.c in movemail in emacs 22 and 23 allows local users
to read, modify, or delete arbitrary mailbox files via a symlink
attack, related to improper file-permission checks.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39155");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/USN-919-1");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0734");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57457");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+bug/531569");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f6b6beaa-4e0e-11df-83fb-0015587e2cc1.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
