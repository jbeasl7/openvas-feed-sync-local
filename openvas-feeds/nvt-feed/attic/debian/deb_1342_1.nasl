# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58514");
  script_cve_id("CVE-2007-3103");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1342-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfs' package(s) announced via the DSA-1342-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1342)' (OID: 1.3.6.1.4.1.25623.1.0.58513).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition in the init.d script of the X Font Server allows the modification of file permissions of arbitrary files if the local administrator can be tricked into restarting the X font server.

For the oldstable distribution (sarge) xfs is present as part of the monolithic xfree86 package. A fix will be provided along with a future security update.

For the stable distribution (etch) this problem has been fixed in version 1.0.1-6.

For the unstable distribution (sid) this problem has been fixed in version 1.0.4-2.

We recommend that you upgrade your xfs package.");

  script_tag(name:"affected", value:"'xfs' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
