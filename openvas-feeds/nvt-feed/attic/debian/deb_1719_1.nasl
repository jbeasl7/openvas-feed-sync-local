# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63392");
  script_cve_id("CVE-2008-4989");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 03:19:21 +0000 (Fri, 09 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1719-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1719-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1719");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls13' package(s) announced via the DSA-1719-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1719.nasl' (OID: 1.3.6.1.4.1.25623.1.0.63392).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martin von Gagern discovered that GNUTLS, an implementation of the TLS/SSL protocol, handles verification of X.509 certificate chains incorrectly if a self-signed certificate is configured as a trusted certificate. This could cause clients to accept forged server certificates as genuine. (CVE-2008-4989)

In addition, this update tightens the checks for X.509v1 certificates which causes GNUTLS to reject certain certificate chains it accepted before. (In certificate chain processing, GNUTLS does not recognize X.509v1 certificates as valid unless explicitly requested by the application.)

For the stable distribution (etch), this problem has been fixed in version 1.4.4-3+etch3.

For the unstable distribution (sid), this problem has been fixed in version 2.4.2-3 of the gnutls26 package.

We recommend that you upgrade your gnutls13 packages.");

  script_tag(name:"affected", value:"'gnutls13' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
