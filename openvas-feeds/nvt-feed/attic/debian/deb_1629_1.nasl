# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61434");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-09-04 17:00:42 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-2936");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1629-1 (postfix)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201629-1");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.mail.postfix.announce/110");
  script_tag(name:"insight", value:"Sebastian Krahmer discovered that Postfix, a mail transfer agent,
incorrectly checks the ownership of a mailbox. In some configurations,
this allows for appending data to arbitrary files as root.

The default Debian installation of Postfix is not affected. Only a
configuration meeting the following requirements is vulnerable:

  * The mail delivery style is mailbox, with the Postfix built-in
local(8) or virtual(8) delivery agents.

  * The mail spool directory is user-writeable.

  * The user can create hardlinks pointing to root-owned symlinks
located in other directories.

For a detailed treating of this issue, please see the referenced upstream
author's announcement.

For the stable distribution (etch), this problem has been fixed in
version 2.3.8-2etch1.

For the testing distribution (lenny), this problem has been fixed in
version 2.5.2-2lenny1.

For the unstable distribution (sid), this problem has been fixed
in version 2.5.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your postfix package.");
  script_tag(name:"summary", value:"The remote host is missing an update to postfix announced via advisory DSA 1629-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1629)' (OID: 1.3.6.1.4.1.25623.1.0.61435).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
