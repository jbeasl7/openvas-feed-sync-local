# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64866");
  script_cve_id("CVE-2007-5624", "CVE-2007-5803", "CVE-2008-1360");
  script_tag(name:"creation_date", value:"2009-09-15 20:46:32 +0000 (Tue, 15 Sep 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1883-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1883");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nagios2' package(s) announced via the DSA-1883-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1883.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64866).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in nagios2, a host/service/network monitoring and management system. The Common Vulnerabilities and Exposures project identifies the following problems:

Several cross-site scripting issues via several parameters were discovered in the CGI scripts, allowing attackers to inject arbitrary HTML code. In order to cover the different attack vectors, these issues have been assigned CVE-2007-5624, CVE-2007-5803 and CVE-2008-1360.

For the oldstable distribution (etch), these problems have been fixed in version 2.6-2+etch4.

The stable distribution (lenny) does not include nagios2, and nagios3 is not affected by these problems.

The testing distribution (squeeze) and the unstable distribution (sid) do not contain nagios2, and nagios3 is not affected by these problems.

We recommend that you upgrade your nagios2 packages.");

  script_tag(name:"affected", value:"'nagios2' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
