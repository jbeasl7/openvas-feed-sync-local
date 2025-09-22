# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57161");
  script_cve_id("CVE-2006-2742", "CVE-2006-2743", "CVE-2006-2831", "CVE-2006-2832", "CVE-2006-2833");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1125-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1125");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal' package(s) announced via the DSA-1125-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1125)' (OID: 1.3.6.1.4.1.25623.1.0.57163).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal update in DSA 1125 contained a regression. This update corrects this flaw. For completeness, the original advisory text below:

Several remote vulnerabilities have been discovered in the Drupal web site platform, which may lead to the execution of arbitrary web script. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-2742

A SQL injection vulnerability has been discovered in the 'count' and 'from' variables of the database interface.

CVE-2006-2743

Multiple file extensions were handled incorrectly if Drupal ran on Apache with mod_mime enabled.

CVE-2006-2831

A variation of CVE-2006-2743 was addressed as well.

CVE-2006-2832

A Cross-Site-Scripting vulnerability in the upload module has been discovered.

CVE-2006-2833

A Cross-Site-Scripting vulnerability in the taxonomy module has been discovered.

For the stable distribution (sarge) these problems have been fixed in version 4.5.3-6.1sarge2.

For the unstable distribution (sid) these problems have been fixed in version 4.5.8-1.1.

We recommend that you upgrade your drupal packages.");

  script_tag(name:"affected", value:"'drupal' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
