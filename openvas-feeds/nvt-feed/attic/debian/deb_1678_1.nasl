# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62840");
  script_cve_id("CVE-2004-0452", "CVE-2005-0448", "CVE-2008-5302", "CVE-2008-5303");
  script_tag(name:"creation_date", value:"2008-12-10 04:23:56 +0000 (Wed, 10 Dec 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1678-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1678");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-1678-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1678)' (OID: 1.3.6.1.4.1.25623.1.0.63059).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Szabo rediscovered a vulnerability in the File::Path::rmtree function of Perl. It was possible to exploit a race condition to create setuid binaries in a directory tree or remove arbitrary files when a process is deleting this tree. This issue was originally known as CVE-2005-0448 and CVE-2004-0452, which were addressed by DSA-696-1 and DSA-620-1. Unfortunately, they were reintroduced later.

For the stable distribution (etch), these problems have been fixed in version 5.8.8-7etch5.

For the unstable distribution (sid), these problems have been fixed in version 5.10.0-18 and will migrate to the testing distribution (lenny) shortly.

We recommend that you upgrade your perl packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
