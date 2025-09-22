# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2199");
  script_tag(name:"creation_date", value:"2023-04-26 04:20:37 +0000 (Wed, 26 Apr 2023)");
  script_version("2024-01-16T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-01-16 05:05:27 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2199)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2199");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2199");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2199");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2199 advisory.

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2199)' (OID: 1.3.6.1.4.1.25623.1.0.69335).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Iceape internet suite, an unbranded version of Seamonkey, updates the certificate blacklist for several fraudulent HTTPS certificates.

More details can be found in a blog posting by Jacob Appelbaum of the Tor project.

The oldstable distribution (lenny) is not affected. The iceape package only provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in version 2.0.11-4.

For the unstable distribution (sid), this problem has been fixed in version 2.0.13-1.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
