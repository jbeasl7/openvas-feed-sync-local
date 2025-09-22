# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53445");
  script_cve_id("CVE-2002-1395");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 202-1 (im)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20202-1");
  script_tag(name:"insight", value:"Tatsuya Kinoshita discovered that IM, which contains interface
commands and Perl libraries for E-mail and NetNews, creates temporary
files insecurely.

1. The impwagent program creates a temporary directory in an insecure
manner in /tmp using predictable directory names without checking
the return code of mkdir, so it's possible to seize a permission
of the temporary directory by local access as another user.

2. The immknmz program creates a temporary file in an insecure manner
in /tmp using a predictable filename, so an attacker with local
access can easily create and overwrite files as another user.

These problems have been fixed in version 141-18.1 for the current
stable distribution (woody), in version 133-2.2 of the old stable
distribution (potato) and in version 141-20 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your IM package.");
  script_tag(name:"summary", value:"The remote host is missing an update to im announced via advisory DSA 202-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-202)' (OID: 1.3.6.1.4.1.25623.1.0.53448).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
