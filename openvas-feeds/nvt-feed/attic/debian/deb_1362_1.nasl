# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58581");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3949", "CVE-2007-3950");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_name("Debian Security Advisory DSA 1362-1 (lighttpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201362-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in lighttpd, a fast webserver with
minimal memory footprint.  The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-3946

The use of mod_auth could leave to a denial of service attack crashing
the webserver

CVE-2007-3947

The improper handling of repeated HTTP headers could cause a denial
of serve attack crashing the webserver.

CVE-2007-3949

A bug in mod_access potentially allows remote users to bypass
access restrictions via trailing slash characters.

CVE-2007-3950

On 32-bit platforms users may be able to create denial of service
attacks, crashing the webserver, via mod_webdav, mod_fastcgi, or
mod_scgi.


For the stable distribution (etch), these problems have been fixed in version
1.4.13-4etch3.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.16-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your lighttpd package.");
  script_tag(name:"summary", value:"The remote host is missing an update to lighttpd announced via advisory DSA 1362-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1362)' (OID: 1.3.6.1.4.1.25623.1.0.58644).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
