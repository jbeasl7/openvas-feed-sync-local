# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64473");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1725", "CVE-2009-1690", "CVE-2009-1687", "CVE-2009-1698", "CVE-2009-0945", "CVE-2009-2537");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-8049 (kdelibs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes several security issues in KHTML (CVE-2009-1725,
CVE-2009-1690, CVE-2009-1687, CVE-2009-1698, CVE-2009-0945, CVE-2009-2537) which
may lead to a denial of service or potentially even arbitrary code execution.
In addition, libplasma was fixed to make Plasmaboard (a virtual keyboard applet)
work, and a bug in a Fedora patch which made builds of the SRPM on single-CPU
machines fail was fixed.
ChangeLog:

  * Sun Jul 26 2009 Kevin Kofler  - 4.2.4-6

  - fix CVE-2009-1725 - crash, possible ACE in numeric character references

  - fix CVE-2009-1690 - crash, possible ACE in KHTML ( use-after-free)

  - fix CVE-2009-1687 - possible ACE in KJS (FIXME: still crashes?)

  - fix CVE-2009-1698 - crash, possible ACE in CSS style attribute handling

  - fix CVE-2009-0945 - NULL-pointer dereference in the SVGList interface impl

  * Thu Jul 23 2009 Jaroslav Reznik  - 4.2.4-5

  - CVE-2009-2537 - select length DoS

  - correct fixPopupForPlasmaboard.patch

  * Wed Jul  8 2009 Kevin Kofler  - 4.2.4-4

  - fix CMake dependency in parallel_devel patch (#510259, CHIKAMA Masaki)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kdelibs' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8049");
  script_tag(name:"summary", value:"The remote host is missing an update to kdelibs
announced via advisory FEDORA-2009-8049.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513813");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505571");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=506453");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=506469");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=506703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512911");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
