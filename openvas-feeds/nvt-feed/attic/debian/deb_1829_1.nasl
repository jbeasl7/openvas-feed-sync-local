# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64416");
  script_cve_id("CVE-2009-2360");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1829-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1829-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1829");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sork-passwd-h3' package(s) announced via the DSA-1829-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1829.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64416).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that sork-passwd-h3, a Horde3 module for users to change their password, is prone to a cross-site scripting attack via the backend parameter.

For the oldstable distribution (etch), this problem has been fixed in version 3.0-2+etch1.

For the stable distribution (lenny), this problem has been fixed in version 3.0-2+lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 3.1-1.1.

We recommend that you upgrade your sork-passwd-h3 packages.");

  script_tag(name:"affected", value:"'sork-passwd-h3' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
