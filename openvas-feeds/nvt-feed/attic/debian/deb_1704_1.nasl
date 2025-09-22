# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63218");
  script_cve_id("CVE-2007-3074", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
  script_tag(name:"creation_date", value:"2009-01-20 21:42:09 +0000 (Tue, 20 Jan 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1704-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1704");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1704-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1704.nasl' (OID: 1.3.6.1.4.1.25623.1.0.63218).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-5500

Jesse Ruderman discovered that the layout engine is vulnerable to DoS attacks that might trigger memory corruption and an integer overflow. (MFSA 2008-60)

CVE-2008-5503

Boris Zbarsky discovered that an information disclosure attack could be performed via XBL bindings. (MFSA 2008-61)

CVE-2008-5506

Marius Schilder discovered that it is possible to obtain sensible data via a XMLHttpRequest. (MFSA 2008-64)

CVE-2008-5507

Chris Evans discovered that it is possible to obtain sensible data via a JavaScript URL. (MFSA 2008-65)

CVE-2008-5508

Chip Salzenberg discovered possible phishing attacks via URLs with leading whitespaces or control characters. (MFSA 2008-66)

CVE-2008-5511

It was discovered that it is possible to perform cross-site scripting attacks via an XBL binding to an 'unloaded document.' (MFSA 2008-68)

CVE-2008-5512

It was discovered that it is possible to run arbitrary JavaScript with chrome privileges via unknown vectors. (MFSA 2008-68)

For the stable distribution (etch) these problems have been fixed in version 1.8.0.15~pre080614i-0etch1.

For the testing distribution (lenny) and the unstable distribution (sid) these problems have been fixed in version 1.9.0.5-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
