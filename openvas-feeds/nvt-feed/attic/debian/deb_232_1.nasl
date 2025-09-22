# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53586");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 01:39:00 +0000 (Sun, 21 Jan 2024)");
  script_name("Debian Security Advisory DSA 232-1 (cupsys)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20232-1");
  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the Common Unix Printing
System (CUPS).  Several of these issues represent the potential for a
remote compromise or denial of service.  The Common Vulnerabilities
and Exposures project identifies the following problems:

. CVE-2002-1383: Multiple integer overflows allow a remote attacker
to execute arbitrary code via the CUPSd HTTP interface and the
image handling code in CUPS filters.

. CVE-2002-1366: Race conditions in connection with /etc/cups/certs/
allow local users with lp privileges to create or overwrite
arbitrary files.  This is not present in the potato version.

. CVE-2002-1367: These vulnerabilities allows a remote attacker to add
printers without authentication via a certain UDP packet, which can
then be used to perform unauthorized activities such as stealing
the local root certificate for the administration server via a
'need authorization' page.

. CVE-2002-1368: Negative lengths fed into memcpy() can cause a
denial of service and possibly execute arbitrary code.

. CVE-2002-1369: An unsafe strncat() function call processing the
options string allows a remote attacker to execute arbitrary code
via a buffer overflow.

. CVE-2002-1371: Zero width images allows a remote attacker to
execute arbitrary code via modified chunk headers.

. CVE-2002-1372: CUPS does not properly check the return values of
various file and socket operations, which could allow a remote
attacker to cause a denial of service.

. CVE-2002-1384: The cupsys package contains some code from the xpdf
package, used to convert PDF files for printing, which contains an
exploitable integer overflow bug.  This is not present in the
potato version.

Even though we tried very hard to fix all problems in the packages for
potato as well, the packages may still contain other security related
problems.  Hence, we advise users of potato systems using CUPS to
upgrade to woody soon.

For the current stable distribution (woody), these problems have been fixed
in version 1.1.14-4.3.

For the old stable distribution (potato), these problems have been fixed
in version 1.0.4-12.1.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.18-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your CUPS packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to cupsys announced via advisory DSA 232-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-232)' (OID: 1.3.6.1.4.1.25623.1.0.53327).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
