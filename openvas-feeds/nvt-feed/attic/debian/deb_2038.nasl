# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68661");
  script_cve_id("CVE-2009-3083", "CVE-2009-3084", "CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_tag(name:"creation_date", value:"2011-01-24 16:55:59 +0000 (Mon, 24 Jan 2011)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2038");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2038");
  script_xref(name:"URL", value:"https://www.backports.org");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pidgin' package(s) announced via the DSA-2038 advisory.

  This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2038-1)' (OID: 1.3.6.1.4.1.25623.1.0.67400).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Pidgin, a multi protocol instant messaging client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0420

Crafted nicknames in the XMPP protocol can crash Pidgin remotely.

CVE-2010-0423

Remote contacts may send too many custom smilies, crashing Pidgin.

Since a few months, Microsoft's servers for MSN have changed the protocol, making Pidgin non-functional for use with MSN. It is not feasible to port these changes to the version of Pidgin in Debian Lenny. This update formalises that situation by disabling the protocol in the client. Users of the MSN protocol are advised to use the version of Pidgin in the repositories of [link moved to references].

For the stable distribution (lenny), these problems have been fixed in version 2.4.3-4lenny6.

For the unstable distribution (sid), these problems have been fixed in version 2.6.6-1.

We recommend that you upgrade your pidgin package.");

  script_tag(name:"affected", value:"'pidgin' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
