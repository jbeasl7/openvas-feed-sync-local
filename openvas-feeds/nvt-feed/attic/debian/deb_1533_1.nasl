# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60654");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-04-07 20:38:54 +0200 (Mon, 07 Apr 2008)");
  script_cve_id("CVE-2007-6354", "CVE-2007-6355", "CVE-2007-6356");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1533-1 (exiftags)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201533-1");
  script_tag(name:"insight", value:"Christian Schmid and Meder Kydyraliev (Google Security) discovered a
number of vulnerabilities in exiftags, a utility for extracting EXIF
metadata from JPEG images. The Common Vulnerabilities and Exposures
project identified the following three problems:

CVE-2007-6354

Inadequate EXIF property validation could lead to invalid memory
accesses if executed on a maliciously crafted image, potentially
including heap corruption and the execution of arbitrary code.

CVE-2007-6355

Flawed data validation could lead to integer overflows, causing
other invalid memory accesses, also with the potential for memory
corruption or arbitrary code execution.

CVE-2007-6356

Cyclical EXIF image file directory (IFD) references could cause
a denial of service (infinite loop).

For the stable distribution (etch), these problems have been fixed in
version 0.98-1.1+etch1.

The old stable distribution (sarge) cannot be fixed synchronously
with the Etch version due to a technical limitation in the Debian
archive management scripts.

For the unstable distribution (sid), these problems have been fixed in
version 1.01-0.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your exiftags package.");
  script_tag(name:"summary", value:"The remote host is missing an update to exiftags announced via advisory DSA 1533-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1533)' (OID: 1.3.6.1.4.1.25623.1.0.60659).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
