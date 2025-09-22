# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61108");
  script_cve_id("CVE-2008-1673", "CVE-2008-2358");
  script_tag(name:"creation_date", value:"2008-06-11 16:37:44 +0000 (Wed, 11 Jun 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1592-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1592");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1592-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1592)' (OID: 1.3.6.1.4.1.25623.1.0.61109).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or arbitrary code execution. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1673

Wei Wang from McAfee reported a potential heap overflow in the ASN.1 decode code that is used by the SNMP NAT and CIFS subsystem. Exploitation of this issue may lead to arbitrary code execution. This issue is not believed to be exploitable with the pre-built kernel images provided by Debian, but it might be an issue for custom images built from the Debian-provided source package.

CVE-2008-2358

Brandon Edwards of McAfee Avert labs discovered an issue in the DCCP subsystem. Due to missing feature length checks it is possible to cause an overflow that may result in remote arbitrary code execution.

For the stable distribution (etch) these problems have been fixed in version 2.6.18.dfsg.1-18etch6.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
