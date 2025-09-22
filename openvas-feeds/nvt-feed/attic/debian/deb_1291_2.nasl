# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58343");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-2446", "CVE-2007-2447");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1291-2 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201291-2");
  script_tag(name:"insight", value:"This update to DSA-1291 covers the old stable version of Debian, 3.1
(sarge).  The current stable distribution, 4.0 (etch) was updated
previously.

Several issues have been identified in Samba, the SMB/CIFS
file- and print-server implementation for GNU/Linux.

CVE-2007-2446
Various bugs in Samba's NDR parsing can allow a user to send specially
crafted MS-RPC requests that will overwrite the heap space with user
defined data.

CVE-2007-2447
Unescaped user input parameters are passed as arguments to /bin/sh
allowing for remote command execution

For the old stable distribution (sarge), these problems have been fixed
in version 3.0.14a-3sarge6");

  script_tag(name:"solution", value:"We recommend that you upgrade your samba package.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba announced via advisory DSA 1291-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1291)' (OID: 1.3.6.1.4.1.25623.1.0.58346).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
