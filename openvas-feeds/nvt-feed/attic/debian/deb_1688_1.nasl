# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63031");
  script_cve_id("CVE-2008-2380", "CVE-2008-2667");
  script_tag(name:"creation_date", value:"2008-12-23 17:28:16 +0000 (Tue, 23 Dec 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1688-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1688");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'courier-authlib' package(s) announced via the DSA-1688-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1688)' (OID: 1.3.6.1.4.1.25623.1.0.63063).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two SQL injection vulnerabilities have been found in courier-authlib, the courier authentication library. The MySQL database interface used insufficient escaping mechanisms when constructing SQL statements, leading to SQL injection vulnerabilities if certain charsets are used (CVE-2008-2380). A similar issue affects the PostgreSQL database interface (CVE-2008-2667).

For the stable distribution (etch), these problems have been fixed in version 0.58-4+etch2.

For the testing distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 0.61.0-1+lenny1.

We recommend that you upgrade your courier-authlib packages.");

  script_tag(name:"affected", value:"'courier-authlib' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
