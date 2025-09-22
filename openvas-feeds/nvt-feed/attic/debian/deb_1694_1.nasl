# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63098");
  script_cve_id("CVE-2008-2383");
  script_tag(name:"creation_date", value:"2009-01-07 22:16:01 +0000 (Wed, 07 Jan 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1694-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1694-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1694");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xterm' package(s) announced via the DSA-1694-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1694.nasl' (OID: 1.3.6.1.4.1.25623.1.0.63098).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Szabo discovered that xterm, a terminal emulator for the X Window System, places arbitrary characters into the input buffer when displaying certain crafted escape sequences (CVE-2008-2383).

As an additional precaution, this security update also disables font changing, user-defined keys, and X property changes through escape sequences.

For the stable distribution (etch), this problem has been fixed in version 222-1etch3.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your xterm package.");

  script_tag(name:"affected", value:"'xterm' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
