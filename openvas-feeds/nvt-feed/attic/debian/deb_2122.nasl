# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68981");
  script_cve_id("CVE-2010-3847", "CVE-2010-3856");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2122");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2122");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glibc' package(s) announced via the DSA-2122 advisory.

  This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2122-1)' (OID: 1.3.6.1.4.1.25623.1.0.68463).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hawkes and Tavis Ormandy discovered that the dynamic loader in GNU libc allows local users to gain root privileges using a crafted LD_AUDIT environment variable.

For the stable distribution (lenny), this problem has been fixed in version 2.7-18lenny6.

For the upcoming stable distribution (squeeze), this problem has been fixed in version 2.11.2-6+squeeze1 of the eglibc package.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your glibc packages.");

  script_tag(name:"affected", value:"'glibc' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
