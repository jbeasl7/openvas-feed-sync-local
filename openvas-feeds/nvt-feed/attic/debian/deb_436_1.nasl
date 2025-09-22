# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53135");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0991", "CVE-2003-0965", "CVE-2003-0038");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 436-1 (mailman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20436-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in the mailman package:

  - CVE-2003-0038 - potential cross-site scripting via certain CGI
parameters (not known to be exploitable in this version)

  - CVE-2003-0965 - cross-site scripting in the administrative
interface

  - CVE-2003-0991 - certain malformed email commands could cause the
mailman process to crash

The cross-site scripting vulnerabilities could allow an attacker to
perform administrative operations without authorization, by stealing a
session cookie.

For the current stable distribution (woody) these problems have been
fixed in version 2.0.11-1woody7.

For the unstable distribution (sid), CVE-2003-0965 is fixed in version
2.1.4-1, and CVE-2003-0038 in version 2.1.1-1.  CVE-2003-0991 will be
fixed soon.

We recommend that you update your mailman package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mailman announced via advisory DSA 436-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-436)' (OID: 1.3.6.1.4.1.25623.1.0.53144).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
