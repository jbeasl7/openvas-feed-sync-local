# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53547");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-0739");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 718-1 (ethereal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20718-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12762");
  script_tag(name:"insight", value:"A buffer overflow has been detected in the IAPP dissector of Ethereal,
a commonly used network traffic analyser.  A remote attacker may be
able to overflow a buffer using a specially crafted packet.  More
problems have been discovered which don't apply to the version in
woody but are fixed in sid as well.

For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody12.

For the unstable distribution (sid) these problems have been fixed in
version 0.10.10-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your ethereal packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to ethereal announced via advisory DSA 718-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-718)' (OID: 1.3.6.1.4.1.25623.1.0.53546).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
