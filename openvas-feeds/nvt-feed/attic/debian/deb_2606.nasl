# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2013.2606");
  script_cve_id("CVE-2012-6095");
  script_tag(name:"creation_date", value:"2023-04-26 04:20:37 +0000 (Wed, 26 Apr 2023)");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2606)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2606");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2606");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2606");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-2606 advisory.

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2606)' (OID: 1.3.6.1.4.1.25623.1.0.702606).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that in ProFTPd, an FTP server, an attacker on the same physical host as the server may be able to perform a symlink attack allowing to elevate privileges in some configurations.

For the stable distribution (squeeze), this problem has been fixed in version 1.3.3a-6squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.3.4a-3.

We recommend that you upgrade your proftpd-dfsg packages.");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
