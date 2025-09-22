# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70715");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3389", "CVE-2012-0036");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-12 06:35:15 -0500 (Sun, 12 Feb 2012)");
  script_name("Debian Security Advisory DSA 2398-1 (curl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202398-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Curl, an URL transfer
library. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2011-3389

This update enables OpenSSL workarounds against the BEAST attack.

CVE-2012-0036

Dan Fandrich discovered that Curl performs insufficient sanitising
when extracting the file path part of an URL.

For the oldstable distribution (lenny), this problem has been fixed in
version 7.18.2-8lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 7.24.0-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to curl announced via advisory DSA 2398-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2398)' (OID: 1.3.6.1.4.1.25623.1.0.71249).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
