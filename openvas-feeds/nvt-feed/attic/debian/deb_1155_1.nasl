# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57299");
  script_cve_id("CVE-2006-1173");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1155-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1155-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1155");
  script_xref(name:"URL", value:"http://ftp.debian.de/debian");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sendmail' package(s) announced via the DSA-1155-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1155)' (OID: 1.3.6.1.4.1.25623.1.0.57300).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It turned out that the sendmail binary depends on libsasl2 (>= 2.1.19.dfsg1) which is neither available in the stable nor in the security archive. This version is scheduled for the inclusion in the next update of the stable release, though.

You'll have to download the referenced file for your architecture from below and install it with dpkg -i.

As an alternative, temporarily adding the following line to /etc/apt/sources.list will mitigate the problem as well:

deb [link moved to references] stable-proposed-updates main

Here is the original security advisory for completeness:

Frank Sheiness discovered that a MIME conversion routine in sendmail, a powerful, efficient, and scalable mail transport agent, could be tricked by a specially crafted mail to perform an endless recursion.

For the stable distribution (sarge) this problem has been fixed in version 8.13.4-3sarge2.

For the unstable distribution (sid) this problem has been fixed in version 8.13.7-1.

We recommend that you upgrade your sendmail package.");

  script_tag(name:"affected", value:"'sendmail' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
