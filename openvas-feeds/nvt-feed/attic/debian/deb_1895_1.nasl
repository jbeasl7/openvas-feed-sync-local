# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64980");
  script_cve_id("CVE-2009-3474", "CVE-2009-3475", "CVE-2009-3476");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1895-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1895-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1895");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xmltooling' package(s) announced via the DSA-1895-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1895.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64980).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the xmltooling packages, as used by Shibboleth:

Chris Ries discovered that decoding a crafted URL leads to a crash (and potentially, arbitrary code execution).

Ian Young discovered that embedded NUL characters in certificate names were not correctly handled, exposing configurations using PKIX trust validation to impersonation attacks.

Incorrect processing of SAML metadata ignores key usage constraints. This minor issue also needs a correction in the opensaml2 packages, which will be provided in an upcoming stable point release (and, before that, via stable-proposed-updates).

For the stable distribution (lenny), these problems have been fixed in version 1.0-2+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1.2.2-1.

We recommend that you upgrade your xmltooling packages.");

  script_tag(name:"affected", value:"'xmltooling' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
