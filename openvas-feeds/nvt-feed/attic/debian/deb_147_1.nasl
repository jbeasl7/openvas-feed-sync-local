# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53409");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0388");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 147-1 (mailman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20147-1");
  script_tag(name:"insight", value:"A cross-site scripting vulnerability was discovered in mailman, a
software to manage electronic mailing lists.  When a properly crafted
URL is accessed with Internet Explorer (other browsers don't seem to
be affected), the resulting webpage is rendered similar to the real
one, but the javascript component is executed as well, which could be
used by an attacker to get access to sensitive information.  The new
version for Debian 2.2 also includes backports of security related
patches from mailman 2.0.11.

This problem has been fixed in version 2.0.11-1woody2 for the current
stable distribution (woody), in version 1.1-10.1 for the old stable
distribution (woody) and in version 2.0.12-1 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your mailman package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mailman announced via advisory DSA 147-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-147)' (OID: 1.3.6.1.4.1.25623.1.0.53415).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
