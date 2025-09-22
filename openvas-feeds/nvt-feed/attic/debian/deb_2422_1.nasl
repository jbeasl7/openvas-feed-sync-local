# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71150");
  script_cve_id("CVE-2012-1571");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-03-12 11:33:02 -0400 (Mon, 12 Mar 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2422-1 (file)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202422-1");
  script_tag(name:"insight", value:"The file type identification tool, file, and its associated library,
libmagic, do not properly process malformed files in the Composite
Document File (CDF) format, leading to crashes.

Note that after this update, file may return different detection
results for CDF files (well-formed or not).  The new detections are
believed to be more accurate.

For the stable distribution (squeeze), this problem has been fixed in
version 5.04-5+squeeze1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your file packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to file announced via advisory DSA 2422-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2422)' (OID: 1.3.6.1.4.1.25623.1.0.71347).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
