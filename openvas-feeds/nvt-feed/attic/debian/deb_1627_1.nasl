# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61379");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
  script_cve_id("CVE-2008-2235");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_name("Debian Security Advisory DSA 1627-1 (opensc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201627-1");
  script_tag(name:"insight", value:"Chaskiel M Grundman discovered that opensc, a library and utilities to
handle smart cards, would initialise smart cards with the Siemens CardOS M4
card operating system without proper access rights. This allowed everyone
to change the card's PIN.

With this bug anyone can change a user PIN without having the PIN or PUK
or the superusers PIN or PUK. However it can not be used to figure out the
PIN. If the PIN on your card is still the same you always had, there's a
reasonable chance that this vulnerability has not been exploited.

This vulnerability affects only smart cards and USB crypto tokens based on
Siemens CardOS M4, and within that group only those that were initialised
with OpenSC. Users of other smart cards and USB crypto tokens, or cards
that have been initialised with some software other than OpenSC, are not
affected.

After upgrading the package, running
pkcs15-tool -T
will show you whether the card is fine or vulnerable. If the card is
vulnerable, you need to update the security setting using:
pkcs15-tool -T -U

For the stable distribution (etch), this problem has been fixed in
version 0.11.1-2etch1.

For the unstable distribution (sid), this problem has been fixed in
version 0.11.4-4.");

  script_tag(name:"solution", value:"We recommend that you upgrade your opensc 0.11.1-2etch1 package and check");
  script_tag(name:"summary", value:"The remote host is missing an update to opensc announced via advisory DSA 1627-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1627)' (OID: 1.3.6.1.4.1.25623.1.0.61590).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
