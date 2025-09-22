# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70693");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2011-4339");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-11 03:21:56 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2376-1 (ipmitool)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202376-1");
  script_tag(name:"insight", value:"It was discovered that OpenIPMI, the Intelligent Platform Management
Interface library and tools, used too wide permissions PID file,
which allows local users to kill arbitrary processes by writing to
this file.

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.11-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.11-5.");

  script_tag(name:"solution", value:"We recommend that you upgrade your ipmitool packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to ipmitool announced via advisory DSA 2376-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2376)' (OID: 1.3.6.1.4.1.25623.1.0.70695).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
