# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53709");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0150");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 458-2 (python2.2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20458-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9836");
  script_tag(name:"insight", value:"This security advisory corrects DSA 458-1 which caused some
segmentation faults in gethostbyaddr with non-localhost input.  This
update also disables IPv6 on all architectures.

The original advisory said:

Sebastian Schmidt discovered a buffer overflow bug in Python's
getaddrinfo function, which could allow an IPv6 address, supplied by a
remote attacker via DNS, to overwrite memory on the stack.

This bug only exists in python 2.2 and 2.2.1, and only when IPv6
support is disabled.  The python2.2 package in Debian woody meets
these conditions (the 'python' package does not).

For the stable distribution (woody), this bug has been fixed in
version 2.2.1-4.5.

The testing and unstable distribution (sid) are not affected by this problem.

We recommend that you update your python2.2 package.");
  script_tag(name:"summary", value:"The remote host is missing an update to python2.2 announced via advisory DSA 458-2.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-458)' (OID: 1.3.6.1.4.1.25623.1.0.53710).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
