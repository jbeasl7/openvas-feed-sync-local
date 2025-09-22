# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53253");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0884");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 563-1 (cyrus-sasl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20563-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11347");
  script_tag(name:"insight", value:"A vulnerability has been discovered in the Cyrus implementation of the
SASL library, the Simple Authentication and Security Layer, a method
for adding authentication support to connection-based protocols.  The
library honors the environment variable SASL_PATH blindly, which
allows a local user to link against a malicious library to run
arbitrary code with the privileges of a setuid or setgid application.

For the stable distribution (woody) this problem has been fixed in
version 1.5.27-3woody2.

For the unstable distribution (sid) this problem has been fixed in
version 1.5.28-6.2 of cyrus-sasl and in version 2.1.19-1.3 of
cyrus-sasl2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libsasl packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to cyrus-sasl announced via advisory DSA 563-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-563)' (OID: 1.3.6.1.4.1.25623.1.0.53252).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
