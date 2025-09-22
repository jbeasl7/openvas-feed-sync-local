# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58357");
  script_cve_id("CVE-2005-4811", "CVE-2006-4623", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-6060", "CVE-2006-6106", "CVE-2006-6535", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1304-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1304-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1304");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.6.8' package(s) announced via the DSA-1304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2006-6060 CVE-2006-6106 CVE-2006-6535 CVE-2007-0958 CVE-2007-1357 CVE-2007-1592

Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code.

This update also fixes a regression in the smbfs subsystem which was introduced in DSA-1233 which caused symlinks to be interpreted as regular files.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4811

David Gibson reported an issue in the hugepage code which could permit a local DoS (system crash) on appropriately configured systems.

CVE-2006-4814

Doug Chapman discovered a potential local DoS (deadlock) in the mincore function caused by improper lock handling.

CVE-2006-4623

Ang Way Chuang reported a remote DoS (crash) in the dvb driver which can be triggered by a ULE package with an SNDU length of 0.

CVE-2006-5753

Eric Sandeen provided a fix for a local memory corruption vulnerability resulting from a misinterpretation of return values when operating on inodes which have been marked bad.

CVE-2006-5754

Darrick Wong discovered a local DoS (crash) vulnerability resulting from the incorrect initialization of nr_pages in aio_setup_ring().

CVE-2006-5757

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted iso9660 filesystem.

CVE-2006-6053

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted ext3 filesystem.

CVE-2006-6056

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted hfs filesystem on systems with SELinux hooks enabled (Debian does not enable SELinux by default).

CVE-2006-6060

LMH reported a potential local DoS (infinite loop) which could be exploited by a malicious user with the privileges to mount and read a corrupted NTFS filesystem.

CVE-2006-6106

Marcel Holtman discovered multiple buffer overflows in the Bluetooth subsystem which can be used to trigger a remote DoS (crash) and potentially execute arbitrary code.

CVE-2006-6535

Kostantin Khorenko discovered an invalid error path in dev_queue_xmit() which could be exploited by a local user to cause data corruption.

CVE-2007-0958

Santosh Eraniose reported a vulnerability that allows local users to read otherwise unreadable files by triggering a core dump while using PT_INTERP. This is related to CVE-2004-1073.

CVE-2007-1357

Jean Delvare reported a vulnerability in the appletalk subsystem. Systems with the appletalk module loaded can be triggered to crash by other systems on the local network via a malformed frame.

CVE-2007-1592

Masayuki Nakagawa discovered that flow labels were inadvertently being shared between listening sockets and child sockets. This defect can be exploited by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-source-2.6.8' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
