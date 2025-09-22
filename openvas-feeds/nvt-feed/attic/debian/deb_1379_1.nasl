# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58639");
  script_cve_id("CVE-2007-5135");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1379-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1379-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1379");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-1379-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1379)' (OID: 1.3.6.1.4.1.25623.1.0.58645).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An off-by-one error has been identified in the SSL_get_shared_ciphers() routine in the libssl library from OpenSSL, an implementation of Secure Socket Layer cryptographic libraries and utilities. This error could allow an attacker to crash an application making use of OpenSSL's libssl library, or potentially execute arbitrary code in the security context of the user running such an application.

For the old stable distribution (sarge), this problem has been fixed in version 0.9.7e-3sarge5.

For the stable distribution (etch), this problem has been fixed in version 0.9.8c-4etch1.

For the unstable and testing distributions (sid and lenny, respectively), this problem has been fixed in version 0.9.8e-9.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
