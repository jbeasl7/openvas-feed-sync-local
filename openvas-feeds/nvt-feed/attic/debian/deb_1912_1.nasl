# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66058");
  script_cve_id("CVE-2009-2660", "CVE-2009-3296");
  script_tag(name:"creation_date", value:"2009-10-19 19:50:22 +0000 (Mon, 19 Oct 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1912-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1912");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'camlimages' package(s) announced via the DSA-1912-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1912.nasl' (OID: 1.3.6.1.4.1.25623.1.0.66058).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CamlImages, an open source image processing library, suffers from several integer overflows, which may lead to a potentially exploitable heap overflow and result in arbitrary code execution. This advisory addresses issues with the reading of TIFF files. It also expands the patch for CVE-2009-2660 to cover another potential overflow in the processing of JPEG images.

For the oldstable distribution (etch), this problem has been fixed in version 2.20-8+etch3.

For the stable distribution (lenny), this problem has been fixed in version 1:2.2.0-4+lenny3.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your camlimages package.");

  script_tag(name:"affected", value:"'camlimages' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
