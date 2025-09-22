# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53682");
  script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-479-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-479");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-kernel-2.4.18-alpha+i386+powerpc' package(s) announced via the DSA-479-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-479)' (OID: 1.3.6.1.4.1.25623.1.0.53176).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several serious problems have been discovered in the Linux kernel. This update takes care of Linux 2.4.18 for the alpha, i386 and powerpc architectures. The Common Vulnerabilities and Exposures project identifies the following problems that will be fixed with this update:

CAN-2004-0003

A vulnerability has been discovered in the R128 DRI driver in the Linux kernel which could potentially lead an attacker to gain unauthorised privileges. Alan Cox and Thomas Biege developed a correction for this.

CAN-2004-0010

Arjan van de Ven discovered a stack-based buffer overflow in the ncp_lookup function for ncpfs in the Linux kernel, which could lead an attacker to gain unauthorised privileges. Petr Vandrovec developed a correction for this.

CAN-2004-0109

zen-parse discovered a buffer overflow vulnerability in the ISO9660 filesystem component of Linux kernel which could be abused by an attacker to gain unauthorised root access. Sebastian Krahmer and Ernie Petrides developed a correction for this.

CAN-2004-0177

Solar Designer discovered an information leak in the ext3 code of Linux. In a worst case an attacker could read sensitive data such as cryptographic keys which would otherwise never hit disk media. Theodore Ts'o developed a correction for this.

CAN-2004-0178

Andreas Kies discovered a denial of service condition in the Sound Blaster driver in Linux. He also developed a correction for this.

These problems are also fixed by upstream in Linux 2.4.26 and will be fixed in Linux 2.6.6.

The following security matrix explains which kernel versions for which architectures are already fixed. Kernel images in the unstable Debian distribution (sid) will be fixed soon.

Architecture

stable (woody)

unstable (sid)

removed in sid

source

2.4.18-14.3

2.4.25-3

  - -

alpha

2.4.18-15

soon

  - -

i386

2.4.18-13

soon

  - -

i386bf

2.4.18-5woody8

soon

  - -

powerpc

2.4.18-1woody5

2.4.25-8

2.4.22

We recommend that you upgrade your kernel packages immediately, either with a Debian provided kernel or with a self compiled one.

Vulnerability matrix for CAN-2004-0109");

  script_tag(name:"affected", value:"'linux-kernel-2.4.18-alpha+i386+powerpc' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
