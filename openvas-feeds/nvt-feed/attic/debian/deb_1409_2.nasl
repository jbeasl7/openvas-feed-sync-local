# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59637");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1409-2 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201409-2");
  script_tag(name:"insight", value:"The previous security update for samba introduced regressions in
the handling of the depreciated filesystem smbfs.  This update fixes
the regression(s) whilst still fixing the security problems.
The original text is reproduced below:

Several local/remote vulnerabilities have been discovered in samba,
a LanManager-like file and printer server for Unix. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5398

Alin Rad Pop of Secunia Research discovered that nmbd did not properly
check the length of netbios packets. When samba is configured as a WINS
server, a remote attacker could send multiple crafted requests resulting
in the execution of arbitrary code with root privileges.

CVE-2007-4572
Samba developers discovered that nmbd could be made to overrun a buffer
during the processing of GETDC logon server requests.  When samba is
configured as a Primary or Backup Domain Controller, a remote attacker
could send malicious logon requests and possibly cause a denial of
service.

For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch7.

For the old stable distribution (sarge), these problems have been fixed in
version 3.0.14a-3sarge9.

For the unstable distribution (sid), these problems have been fixed in
version 3.0.27-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba announced via advisory DSA 1409-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1409)' (OID: 1.3.6.1.4.1.25623.1.0.59917).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
