# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71263");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-30 07:58:15 -0400 (Mon, 30 Apr 2012)");
  script_name("Debian Security Advisory DSA 2459-1 (quagga)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202459-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Quagga, a routing
daemon.

CVE-2012-0249
A buffer overflow in the ospf_ls_upd_list_lsa function in the
OSPFv2 implementation allows remote attackers to cause a
denial of service (assertion failure and daemon exit) via a
Link State Update (aka LS Update) packet that is smaller than
the length specified in its header.

CVE-2012-0250
A buffer overflow in the OSPFv2 implementation allows remote
attackers to cause a denial of service (daemon crash) via a
Link State Update (aka LS Update) packet containing a
network-LSA link-state advertisement for which the
data-structure length is smaller than the value in the Length
header field.

CVE-2012-0255
The BGP implementation does not properly use message buffers
for OPEN messages, which allows remote attackers impersonating
a configured BGP peer to cause a denial of service (assertion
failure and daemon exit) via a message associated with a
malformed AS4 capability.

This security update upgrades the quagga package to the most recent
upstream release.  This release includes other corrections, such as
hardening against unknown BGP path attributes.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.20.1-0+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 0.99.20.1-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your quagga packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to quagga announced via advisory DSA 2459-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2459)' (OID: 1.3.6.1.4.1.25623.1.0.71342).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
