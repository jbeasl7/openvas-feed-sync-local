# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66581");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3547", "CVE-2009-3638", "CVE-2009-3624", "CVE-2009-3621", "CVE-2009-3620", "CVE-2009-3612", "CVE-2009-2909", "CVE-2009-2908", "CVE-2009-2903", "CVE-2009-3290", "CVE-2009-2847", "CVE-2009-4410");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-03 17:13:00 +0000 (Fri, 03 Nov 2023)");
  script_name("Fedora Core 11 FEDORA-2009-13694 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Fix a local DoS when using fuse.

ChangeLog:

  * Thu Dec 24 2009 Kyle McMartin  2.6.30.10-105

  - fuse: fix kunmap in fuse_ioctl_copy_user, #549400

  * Tue Dec  8 2009 Chuck Ebbert  2.6.30.10-104

  - Copy fix for #540580 from F-12.

  * Fri Dec  4 2009 Kyle McMartin  2.6.30.10-103

  - 2.6.30.10

  - nuke ipv4-fix-null-ptr-deref-in-ip_fragment.patch, it's in the latest
stable release.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13694");
  script_tag(name:"summary", value:"The remote host is missing an update to the linux kernel
announced via advisory FEDORA-2009-13694.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=549400");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
