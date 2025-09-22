# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57070");
  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1104-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1104");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1104-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1104)' (OID: 1.3.6.1.4.1.25623.1.0.57071).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Loading malformed XML documents can cause buffer overflows in OpenOffice.org, a free office suite, and cause a denial of service or execute arbitrary code. It turned out that the correction in DSA 1104-1 was not sufficient, hence, another update. For completeness please find the original advisory text below:

Several vulnerabilities have been discovered in OpenOffice.org, a free office suite. The Common Vulnerabilities and Exposures Project identifies the following problems:

CVE-2006-2198

It turned out to be possible to embed arbitrary BASIC macros in documents in a way that OpenOffice.org does not see them but executes them anyway without any user interaction.

CVE-2006-2199

It is possible to evade the Java sandbox with specially crafted Java applets.

CVE-2006-3117

Loading malformed XML documents can cause buffer overflows and cause a denial of service or execute arbitrary code.

This update has the Mozilla component disabled, so that the Mozilla/LDAP addressbook feature won't work anymore. It didn't work on anything else than i386 on sarge either.

The old stable distribution (woody) does not contain OpenOffice.org packages.

For the stable distribution (sarge) this problem has been fixed in version 1.1.3-9sarge3.

For the unstable distribution (sid) this problem has been fixed in version 2.0.3-1.

We recommend that you upgrade your OpenOffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
