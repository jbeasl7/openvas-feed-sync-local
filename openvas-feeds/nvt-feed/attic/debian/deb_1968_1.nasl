# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66734");
  script_cve_id("CVE-2009-4009", "CVE-2009-4010");
  script_tag(name:"creation_date", value:"2010-01-20 19:07:43 +0000 (Wed, 20 Jan 2010)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1968-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1968-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1968");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns-recursor' package(s) announced via the DSA-1968-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1968.nasl' (OID: 1.3.6.1.4.1.25623.1.0.66734).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that pdns-recursor, the PowerDNS recursive name server, contains several vulnerabilities:

CVE-2009-4009

A buffer overflow can be exploited to crash the daemon, or potentially execute arbitrary code.

CVE-2009-4010

A cache poisoning vulnerability may allow attackers to trick the server into serving incorrect DNS data.

For the oldstable distribution (etch), fixed packages will be provided soon.

For the stable distribution (lenny), these problems have been fixed in version 3.1.7-1+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 3.1.7.2-1.

We recommend that you upgrade your pdns-recursor package.");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
