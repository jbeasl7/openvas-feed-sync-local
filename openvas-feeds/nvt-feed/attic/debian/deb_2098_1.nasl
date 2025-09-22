# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67985");
  script_cve_id("CVE-2010-3659", "CVE-2010-3660", "CVE-2010-3661", "CVE-2010-3662", "CVE-2010-3663", "CVE-2010-3664", "CVE-2010-3665", "CVE-2010-3666", "CVE-2010-3667", "CVE-2010-3668", "CVE-2010-3669", "CVE-2010-3670", "CVE-2010-3671", "CVE-2010-3672", "CVE-2010-3673", "CVE-2010-3674");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 17:57:00 +0000 (Fri, 08 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-2098-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2098-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2098");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2098-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_2098.nasl' (OID: 1.3.6.1.4.1.25623.1.0.67985).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web content management framework: cross-site Scripting, open redirection, SQL injection, broken authentication and session management, insecure randomness, information disclosure and arbitrary code execution. More details can be found in the Typo3 security advisory.

For the stable distribution (lenny), these problems have been fixed in version 4.2.5-1+lenny4.

The testing distribution (squeeze) will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 4.3.5-1.

We recommend that you upgrade your typo3-src package.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
