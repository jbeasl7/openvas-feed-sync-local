# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53703");
  script_cve_id("CVE-2004-0488", "CVE-2004-0700");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-532-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-532");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache-mod-ssl' package(s) announced via the DSA-532-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-532)' (OID: 1.3.6.1.4.1.25623.1.0.53224).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in libapache-mod-ssl:

CAN-2004-0488

Stack-based buffer overflow in the ssl_util_uuencode_binary function in ssl_util.c for Apache mod_ssl, when mod_ssl is configured to trust the issuing CA, may allow remote attackers to execute arbitrary code via a client certificate with a long subject DN.

CAN-2004-0700

Format string vulnerability in the ssl_log function in ssl_engine_log.c in mod_ssl 2.8.19 for Apache 1.3.31 may allow remote attackers to execute arbitrary messages via format string specifiers in certain log messages for HTTPS.

For the current stable distribution (woody), these problems have been fixed in version 2.8.9-2.4.

For the unstable distribution (sid), CAN-2004-0488 was fixed in version 2.8.18, and CAN-2004-0700 will be fixed soon.

We recommend that you update your libapache-mod-ssl package.");

  script_tag(name:"affected", value:"'libapache-mod-ssl' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
