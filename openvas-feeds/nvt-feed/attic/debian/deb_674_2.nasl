# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53505");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-1177", "CVE-2005-0202");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 674-2 (mailman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20674-2");
  script_tag(name:"insight", value:"Due to an error the last mailman update was slightly broken and had to
be corrected.  This advisory only updates the packages updated with
DSA 674-1.  For completeness below is the original advisory text:

Two security related problems have been discovered in mailman,
web-based GNU mailing list manager.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2004-1177

Florian Weimer discovered a cross-site scripting vulnerability in
mailman's automatically generated error messages.  An attacker
could craft an URL containing JavaScript (or other content
embedded into HTML) which triggered a mailman error page that
would include the malicious code verbatim.

CVE-2005-0202

Several listmasters have noticed unauthorised access to archives
of private lists and the list configuration itself, including the
users passwords.  Administrators are advised to check the
webserver logfiles for requests that contain /...../ and the
path to the archives or configuration.  This does only seem to
affect installations running on web servers that do not strip
slashes, such as Apache 1.3.

For the stable distribution (woody) these problems have been fixed in
version 2.0.11-1woody10.

For the unstable distribution (sid) these problems have been fixed in
version 2.1.5-6.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mailman package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mailman announced via advisory DSA 674-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-674)' (OID: 1.3.6.1.4.1.25623.1.0.53517).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
