# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53438");
  script_cve_id("CVE-2002-1275");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 192-1 (html2ps)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20192-1");
  script_tag(name:"insight", value:"The SuSE Security Team found a vulnerability in html2ps, a HTML to
PostScript converter, that opened files based on unsanitized input
insecurely.  This problem can be exploited when html2ps is installed
as filter within lrpng and the attacker has previously gained access
to the lp account.

These problems have been fixed in version 1.0b3-1.1 for the current
stable distribution (woody), in version 1.0b1-8.1 for the old stable
distribution (potato) and in version 1.0b3-2 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your html2ps package.");
  script_tag(name:"summary", value:"The remote host is missing an update to html2ps announced via advisory DSA 192-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-192)' (OID: 1.3.6.1.4.1.25623.1.0.53449).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
