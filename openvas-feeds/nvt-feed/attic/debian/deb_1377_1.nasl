# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58615");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-4565");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 1377-1 (fetchmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201377-1");
  script_tag(name:"insight", value:"Matthias Andree discovered that fetchmail, an SSL enabled POP3, APOP
and IMAP mail gatherer/forwarder, can under certain circumstances
attempt to dereference a NULL pointer and crash.

For the stable distribution (etch), this problem has been fixed in
version 6.3.6-1etch1.

For the old stable distribution (sarge), this problem was not present.

For the unstable distribution (sid), this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your fetchmail package.");
  script_tag(name:"summary", value:"The remote host is missing an update to fetchmail announced via advisory DSA 1377-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1377)' (OID: 1.3.6.1.4.1.25623.1.0.58616).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
