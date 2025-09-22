# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64297");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");
  script_name("Fedora Core 11 FEDORA-2009-6261 (apr-util)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to upstream version 1.3.7

Security fixes:

  - CVE-2009-0023 Fix underflow in apr_strmatch_precompile.

  - CVE-2009-1955 Fix a denial of service attack against the
  apr_xml_* interface using the billion laughs entity expansion technique.

  - CVE-2009-1956 Fix off by one overflow in apr_brigade_vprintf.
  Note: CVE-2009-1956 is only an issue on big-endian architectures.

ChangeLog:

  * Mon Jun  8 2009 Bojan Smojver  - 1.3.7-1

  - bump up to 1.3.7

  - CVE-2009-0023

  - billion laughs fix of apr_xml_* interface");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update apr-util' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6261");
  script_tag(name:"summary", value:"The remote host is missing an update to apr-util
announced via advisory FEDORA-2009-6261.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504555");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504390");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503928");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
