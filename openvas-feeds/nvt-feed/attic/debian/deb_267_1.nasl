# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53338");
  script_cve_id("CVE-2003-0144");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-267-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-267-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-267");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lpr' package(s) announced via the DSA-267-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-267)' (OID: 1.3.6.1.4.1.25623.1.0.53358).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow has been discovered in lpr, a BSD lpr/lpd line printer spooling system. This problem can be exploited by a local user to gain root privileges, even if the printer system is set up properly.

For the stable distribution (woody) this problem has been fixed in version 2000.05.07-4.3.

For the old stable distribution (potato) this problem has been fixed in version 0.48-1.1.

For the unstable distribution (sid) this problem has been fixed in version 2000.05.07-4.20.

We recommend that you upgrade your lpr package immediately.");

  script_tag(name:"affected", value:"'lpr' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
