# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55901");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-3088");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 900-2 (fetchmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge3.

For the unstable distribution (sid) this problem has been fixed in
version 6.2.5.4-1.

  We recommend that you upgrade your fetchmail package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20900-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15179");
  script_tag(name:"summary", value:"The remote host is missing an update to fetchmail announced via advisory DSA 900-2.  Due to restrictive dependency definition the updated fetchmailconf package couldn't be installed on the old stable distribution (woody) together with fetchmail-ssl.  Hence, this update loosens it, so that the update can be pulled in.  For completeness we're including the original advisory text:  Thomas Wolff discovered that the fetchmailconfig program which is provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail gatherer/forwarder, creates the new configuration in an insecure fashion that can lead to leaking passwords for mail accounts to local users.  This update also fixes a regression in the package for stable caused by the last security update.  For the old stable distribution (woody) this problem has been fixed in version 5.9.11-6.4.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-900)' (OID: 1.3.6.1.4.1.25623.1.0.55908).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
