# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53130");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0618");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 431-1 (perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20431-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9543");
  script_tag(name:"insight", value:"Paul Szabo discovered a number of similar bugs in suidperl, a helper
program to run perl scripts with setuid privileges.  By exploiting
these bugs, an attacker could abuse suidperl to discover information
about files (such as testing for their existence and some of their
permissions) that should not be accessible to unprivileged users.

For the current stable distribution (woody) this problem has been
fixed in version 5.6.1-8.6.

For the unstable distribution, this problem will be fixed soon.  Refer
to Debian bug #220486.

We recommend that you update your perl package if you have the
perl-suid package installed.");
  script_tag(name:"summary", value:"The remote host is missing an update to perl announced via advisory DSA 431-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-431)' (OID: 1.3.6.1.4.1.25623.1.0.53180).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
