# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63406");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
  script_cve_id("CVE-2008-1447");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)");
  script_name("Fedora Core 9 FEDORA-2009-1069 (dnsmasq)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to newer upstream version - 2.45.
Version of dnsmasq previously shipped in Fedora 9 did not
properly drop privileges, causing it to run as root
instead of intended user nobody.  Issue was caused by a
bug in kernel-headers used in build environment of the original
packages. (#454415)

New upstream version also adds DNS query source port
randomization, mitigating DNS spoofing attacks. (CVE-2008-1447)

ChangeLog:

  * Mon Jul 21 2008 Patrick Jima Laughton  2.45-1

  - Upstream release (bugfixes)

  * Wed Jul 16 2008 Patrick Jima Laughton  2.43-2

  - New upstream release, contains fixes for CVE-2008-1447/CERT VU#800113

  - Dropped patch for newer glibc (merged upstream)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update dnsmasq' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1069");
  script_tag(name:"summary", value:"The remote host is missing an update to dnsmasq
announced via advisory FEDORA-2009-1069.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=449345");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
