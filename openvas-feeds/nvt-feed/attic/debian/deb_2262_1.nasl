# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69967");
  script_cve_id("CVE-2011-4133", "CVE-2011-4278", "CVE-2011-4283", "CVE-2011-4286", "CVE-2011-4288", "CVE-2011-4290");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2262-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2262-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2262");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-2262-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_2262.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69967).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several cross-site scripting and information disclosure issues have been fixed in Moodle, a course management system for online learning:

MSA-11-0002

Cross-site request forgery vulnerability in RSS block

MSA-11-0003

Cross-site scripting vulnerability in tag autocomplete

MSA-11-0008

IMS enterprise enrolment file may disclose sensitive information

MSA-11-0011

Multiple cross-site scripting problems in media filter

MSA-11-0015

Cross Site Scripting through URL encoding

MSA-11-0013

Group/Quiz permissions issue

For the stable distribution (squeeze), this problem has been fixed in version 1.9.9.dfsg2-2.1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 1.9.9.dfsg2-3.

We recommend that you upgrade your moodle packages.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
