# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57329");
  script_cve_id("CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3811");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1161-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1161");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-1161-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1161)' (OID: 1.3.6.1.4.1.25623.1.0.57378).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The latest security updates of Mozilla Firefox introduced a regression that led to a dysfunctional attachment panel which warrants a correction to fix this issue. For reference please find below the original advisory text:

Several security related problems have been discovered in Mozilla and derived products like Mozilla Firefox. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-3805

The Javascript engine might allow remote attackers to execute arbitrary code. [MFSA-2006-50]

CVE-2006-3806

Multiple integer overflows in the Javascript engine might allow remote attackers to execute arbitrary code. [MFSA-2006-50]

CVE-2006-3807

Specially crafted Javascript allows remote attackers to execute arbitrary code. [MFSA-2006-51]

CVE-2006-3808

Remote Proxy AutoConfig (PAC) servers could execute code with elevated privileges via a specially crafted PAC script. [MFSA-2006-52]

CVE-2006-3809

Scripts with the UniversalBrowserRead privilege could gain UniversalXPConnect privileges and possibly execute code or obtain sensitive data. [MFSA-2006-53]

CVE-2006-3811

Multiple vulnerabilities allow remote attackers to cause a denial of service (crash) and possibly execute arbitrary code. [MFSA-2006-55]

For the stable distribution (sarge) these problems have been fixed in version 1.0.4-2sarge11.

For the unstable distribution (sid) these problems have been fixed in version 1.5.dfsg+1.5.0.5-1.

We recommend that you upgrade your mozilla-firefox package.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
