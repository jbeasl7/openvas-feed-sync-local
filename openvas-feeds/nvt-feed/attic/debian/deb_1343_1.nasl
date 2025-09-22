# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58515");
  script_cve_id("CVE-2007-2799");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1343-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1343");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'file' package(s) announced via the DSA-1343-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1343)' (OID: 1.3.6.1.4.1.25623.1.0.58635).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Colin Percival discovered an integer overflow in file, a file type classification tool, which may lead to the execution of arbitrary code.

For the oldstable distribution (sarge) this problem has been fixed in version 4.12-1sarge2.

For the stable distribution (etch) this problem has been fixed in version 4.17-5etch2.

For the unstable distribution (sid) this problem has been fixed in version 4.21-1.

We recommend that you upgrade your file package.");

  script_tag(name:"affected", value:"'file' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
