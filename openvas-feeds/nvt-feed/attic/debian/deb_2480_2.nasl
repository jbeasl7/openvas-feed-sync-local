# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71359");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-05-31 11:52:12 -0400 (Thu, 31 May 2012)");
  script_name("Debian Security Advisory DSA 2480-2 (request-tracker3.8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202480-2");
  script_tag(name:"insight", value:"It was discovered that the recent request-tracker3.8 update,
DSA-2480-1, introduced a regression which caused outgoing mail to fail
when running under mod_perl.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually.  The restart
mechanism is not recommended, especially when using mod_perl.

For the stable distribution (squeeze), this problem has been fixed in
version 3.8.8-7+squeeze3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your request-tracker3.8 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to request-tracker3.8 announced via advisory DSA 2480-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2480)' (OID: 1.3.6.1.4.1.25623.1.0.71465).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
