# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53158");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0108");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 460-1 (sysstat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20460-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9844");
  script_tag(name:"insight", value:"Alan Cox discovered that the isag utility (which graphically displays
data collected by the sysstat tools), creates a temporary file without
taking proper precautions.  This vulnerability could allow a local
attacker to overwrite files with the privileges of the user invoking
isag.

For the current stable distribution (woody) this problem has been
fixed in version 5.0.1-1.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you update your sysstat package.");
  script_tag(name:"summary", value:"The remote host is missing an update to sysstat announced via advisory DSA 460-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-460)' (OID: 1.3.6.1.4.1.25623.1.0.53173).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
