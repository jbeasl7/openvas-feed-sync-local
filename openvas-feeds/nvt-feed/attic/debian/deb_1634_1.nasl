# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61592");
  script_cve_id("CVE-2008-2149", "CVE-2008-3908");
  script_tag(name:"creation_date", value:"2008-09-17 02:23:15 +0000 (Wed, 17 Sep 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1634-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1634");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordnet' package(s) announced via the DSA-1634-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1634)' (OID: 1.3.6.1.4.1.25623.1.0.61643).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rob Holland discovered several programming errors in WordNet, an electronic lexical database of the English language. These flaws could allow arbitrary code execution when used with untrusted input, for example when WordNet is in use as a back end for a web application.

For the stable distribution (etch), these problems have been fixed in version 1:2.1-4+etch1.

For the testing distribution (lenny), these problems have been fixed in version 1:3.0-11+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1:3.0-12.

We recommend that you upgrade your wordnet package.");

  script_tag(name:"affected", value:"'wordnet' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
