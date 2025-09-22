# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71358");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2082", "CVE-2011-2083", "CVE-2011-2084", "CVE-2011-2085", "CVE-2011-4458", "CVE-2011-4459", "CVE-2011-4460", "CVE-2011-0009");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-05-31 11:52:03 -0400 (Thu, 31 May 2012)");
  script_name("Debian Security Advisory DSA 2480-1 (request-tracker3.8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202480-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Request Tracker, an issue
tracking system:

CVE-2011-2082

The vulnerable-passwords scripts introduced for CVE-2011-0009
failed to correct the password hashes of disabled users.

CVE-2011-2083

Several cross-site scripting issues have been discovered.

CVE-2011-2084

Password hashes could be disclosed by privileged users.

CVE-2011-2085

Several cross-site request forgery vulnerabilities have been
found. If this update breaks your setup, you can restore the old
behaviour by setting $RestrictReferrer to 0.

CVE-2011-4458

The code to support variable envelope return paths allowed the
execution of arbitrary code.

CVE-2011-4459

Disabled groups were not fully accounted as disabled.

CVE-2011-4460

SQL injection vulnerability, only exploitable by privileged users.


For the stable distribution (squeeze), this problem has been fixed in
version 3.8.8-7+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 4.0.5-3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your request-tracker3.8 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to request-tracker3.8 announced via advisory DSA 2480-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2480)' (OID: 1.3.6.1.4.1.25623.1.0.71359).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
