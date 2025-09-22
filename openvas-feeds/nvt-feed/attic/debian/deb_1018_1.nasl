# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56471");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3257", "CVE-2005-3783", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4618");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Debian Security Advisory DSA 1018-1 (kernel-source-2.4.27)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201018-1");
  script_tag(name:"insight", value:"The following matrix explains which kernel version for which architecture
fix the problems addressed with this update:

Debian 3.1 (sarge)
Source                          2.4.27-10sarge2
Alpha architecture              2.4.27-10sarge2
ARM architecture                2.4.27-2sarge2
Intel IA-32 architecture        2.4.27-10sarge2
Intel IA-64 architecture        2.4.27-10sarge2
Motorola 680x0 architecture     2.4.27-3sarge2
Big endian MIPS architecture    2.4.27-10.sarge1.040815-2
Little endian MIPS architecture 2.4.27-10.sarge1.040815-2
PowerPC architecture            2.4.27-10sarge2
IBM S/390 architecture          2.4.27-2sarge2
Sun Sparc architecture          2.4.27-9sarge2

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 3.1 (sarge)
kernel-latest-2.4-alpha         101sarge1
kernel-latest-2.4-i386          101sarge1
kernel-latest-2.4-s390          2.4.27-1sarge1
kernel-latest-2.4-sparc         42sarge1
kernel-latest-powerpc           102sarge1
fai-kernels                     1.9.1sarge1
i2c                             1:2.9.1-1sarge1
kernel-image-speakup-i386       2.4.27-1.1sasrge1
lm-sensors                      1:2.9.1-1sarge3
mindi-kernel                    2.4.27-2sarge1
pcmcia-modules-2.4.27-i386      3.2.5+2sarge1
systemimager                    3.2.3-6sarge1");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel package immediately and reboot");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-source-2.4.27 announced via advisory DSA 1018-1. For details on the issues addressed with this update, please visit the referenced security advisories.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1018)' (OID: 1.3.6.1.4.1.25623.1.0.56533).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
