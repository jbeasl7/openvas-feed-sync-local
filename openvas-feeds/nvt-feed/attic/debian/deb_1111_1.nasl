# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57108");
  script_cve_id("CVE-2006-3626");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1111-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1111-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1111");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.6.8' package(s) announced via the DSA-1111-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1111)' (OID: 1.3.6.1.4.1.25623.1.0.57160).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition in the process filesystem can lead to privilege escalation.

The following matrix explains which kernel version for which architecture fixes the problem mentioned above:



Debian 3.1 (sarge)

Source                      2.6.8-16sarge4

Alpha architecture          2.6.8-16sarge4

AMD64 architecture          2.6.8-16sarge4

Intel IA-32 architecture    2.6.8-16sarge4

Intel IA-64 architecture    2.6.8-14sarge4

PowerPC architecture        2.6.8-12sarge4

Sun Sparc architecture      2.6.8-15sarge4

IBM S/390                   2.6.8-5sarge4

Motorola 680x0              2.6.8-4sarge4

HP Precision                2.6.8-6sarge3

FAI                         1.9.1sarge3

The initial advisory lacked builds for the IBM S/390, Motorola 680x0 and HP Precision architectures, which are now provided. Also, the kernels for the FAI installer have been updated.

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'kernel-source-2.6.8' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
