# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64728");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-1391", "CVE-2009-1884");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-8888 (perl-Compress-Raw-Bzip2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Off-by-one error in the bzinflate function in Bzip2.xs in the
Compress-Raw-Bzip2 module before 2.018 for Perl allows
context-dependent attackers to cause a denial of service
(application hang or crash) via a crafted bzip2 compressed
stream that triggers a buffer overflow, a related issue to CVE-2009-1391.

ChangeLog:

  * Thu Aug 20 2009 Marcela Maláová  - 2.020-1

  - 518278 CVE-2009-1884, update to the latest release");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl-Compress-Raw-Bzip2' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8888");
  script_tag(name:"summary", value:"The remote host is missing an update to perl-Compress-Raw-Bzip2
announced via advisory FEDORA-2009-8888.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=518278");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
