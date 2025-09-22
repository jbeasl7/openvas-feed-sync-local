# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63835");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
  script_cve_id("CVE-2009-0792", "CVE-2009-0196", "CVE-2008-6679", "CVE-2009-0583", "CVE-2009-0584");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3709 (ghostscript)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes several security flaws: CVE-2009-0792 (multiple integer
overflows and missing upper-bounds checks in icclib), CVE-2009-0196 (missing
boundary check in jbig2dec library), and CVE-2008-6679 (buffer overflow in
pdfwrite device).");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update ghostscript' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3709");
  script_tag(name:"summary", value:"The remote host is missing an update to ghostscript
announced via advisory FEDORA-2009-3709.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=493445");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=493379");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=491853");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
