# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56219");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-4536");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 960-2 (libmail-audit-perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 2.1-5sarge2.

For the unstable distribution (sid) these problems have been fixed in
version 2.1-5.1.

  We recommend that you upgrade your libmail-audit-perl package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20960-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16434");
  script_tag(name:"summary", value:"The remote host is missing an update to libmail-audit-perl announced via advisory DSA 960-2.  This update only corrects the update for sarge, the version in woody is correct.  Niko Tyni discovered that the Mail::Audit module, a Perl library for creating simple mail filters, logs to a temporary file with a predictable filename in an insecure fashion when logging is turned on, which is not the case by default.  For the old stable distribution (woody) these problems have been fixed in version 2.0-4woody1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-960)' (OID: 1.3.6.1.4.1.25623.1.0.56460).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
