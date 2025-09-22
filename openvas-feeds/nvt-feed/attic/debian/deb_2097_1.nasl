# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67984");
  script_cve_id("CVE-2010-3055", "CVE-2010-3056");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2097-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2097-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2097");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-2097-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_2097.nasl' (OID: 1.3.6.1.4.1.25623.1.0.67984).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpMyAdmin, a tool to administer MySQL over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3055

The configuration setup script does not properly sanitise its output file, which allows remote attackers to execute arbitrary PHP code via a crafted POST request. In Debian, the setup tool is protected through Apache HTTP basic authentication by default.

CVE-2010-3056

Various cross site scripting issues have been discovered that allow a remote attacker to inject arbitrary web script or HTML.

For the stable distribution (lenny), these problems have been fixed in version 2.11.8.1-5+lenny5.

For the testing (squeeze) and unstable distribution (sid), these problems have been fixed in version 3.3.5.1-1.

We recommend that you upgrade your phpmyadmin package.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
