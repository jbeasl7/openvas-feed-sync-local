# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53363");
  script_cve_id("CVE-2003-0214");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-292-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-292");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mime-support' package(s) announced via the DSA-292-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-292)' (OID: 1.3.6.1.4.1.25623.1.0.53364).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Colin Phipps discovered several problems in mime-support, that contains support programs for the MIME control files 'mime.types' and 'mailcap'. When a temporary file is to be used it is created insecurely, allowing an attacker to overwrite arbitrary under the user id of the person executing run-mailcap.

When run-mailcap is executed on a file with a potentially problematic filename, a temporary file is created (not insecurely anymore), removed and a symbolic link to this filename is created. An attacker could recreate the file before the symbolic link is created, forcing the display program to display different content.

For the stable distribution (woody) these problems have been fixed in version 3.18-1.3.

For the old stable distribution (potato) these problems have been fixed in version 3.9-1.3.

For the unstable distribution (sid) these problems have been fixed in version 3.23-1.

We recommend that you upgrade your mime-support packages.");

  script_tag(name:"affected", value:"'mime-support' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
