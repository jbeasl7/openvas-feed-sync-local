# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60437");
  script_cve_id("CVE-2004-2731", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6106", "CVE-2007-1353", "CVE-2007-1592", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4311", "CVE-2007-5093", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0007");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1503-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1503");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernelimage-2.4.27' package(s) announced via the DSA-1503-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1503)' (OID: 1.3.6.1.4.1.25623.1.0.60498).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-2731

infamous41md reported multiple integer overflows in the Sbus PROM driver that would allow for a DoS (Denial of Service) attack by a local user, and possibly the execution of arbitrary code.

CVE-2006-4814

Doug Chapman discovered a potential local DoS (deadlock) in the mincore function caused by improper lock handling.

CVE-2006-5753

Eric Sandeen provided a fix for a local memory corruption vulnerability resulting from a misinterpretation of return values when operating on inodes which have been marked bad.

CVE-2006-5823

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted cramfs filesystem.

CVE-2006-6053

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted ext3 filesystem.

CVE-2006-6054

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted ext2 filesystem.

CVE-2006-6106

Marcel Holtman discovered multiple buffer overflows in the Bluetooth subsystem which can be used to trigger a remote DoS (crash) and potentially execute arbitrary code.

CVE-2007-1353

Ilja van Sprundel discovered that kernel memory could be leaked via the Bluetooth setsockopt call due to an uninitialized stack buffer. This could be used by local attackers to read the contents of sensitive kernel memory.

CVE-2007-1592

Masayuki Nakagawa discovered that flow labels were inadvertently being shared between listening sockets and child sockets. This defect can be exploited by local users to cause a DoS (Oops).

CVE-2007-2172

Thomas Graf reported a typo in the DECnet protocol handler that could be used by a local attacker to overrun an array via crafted packets, potentially resulting in a Denial of Service (system crash). A similar issue exists in the IPV4 protocol handler and will be fixed in a subsequent update.

CVE-2007-2525

Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused by releasing a socket before PPPIOCGCHAN is called upon it. This could be used by a local user to DoS a system by consuming all available memory.

CVE-2007-3848

Wojciech Purczynski discovered that pdeath_signal was not being reset properly under certain conditions which may allow local users to gain privileges by sending arbitrary signals to suid binaries.

CVE-2007-4308

Alan Cox reported an issue in the aacraid driver that allows unprivileged local users to make ioctl calls which should be restricted to admin privileges.

CVE-2007-4311

PaX team discovered an issue in the random driver where a defect in the reseeding code ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernelimage-2.4.27' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
