# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64761");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2008-5033", "CVE-2009-0676", "CVE-2009-1046", "CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1758", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");
  script_name("SUSE: Security Advisory for kernel (SUSE-SA:2009:045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"The Linux kernel update fixes the following security issues:

CVE-2009-2692: A missing NULL pointer check in the socket sendpage
function can be used by local attackers to gain root privileges.
[SLES9, SLES10-SP2, SLE11, openSUSE]

CVE-2009-1389: A crash on r8169 network cards when receiving
large packets was fixed.
[SLES9, SLES10-SP2, SLE11, openSUSE]

CVE-2009-1758: The hypervisor_callback function in Xen allows guest
user applications to cause a denial of service (kernel oops) of the
guest OS by triggering a segmentation fault in certain address
ranges.
[SLES9, SLES10-SP2, SLE11, openSUSE]

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c in the
NFS client implementation in the Linux kernel, when atomic_open is
available, does not check execute (aka EXEC or MAY_EXEC) permission
bits, which allows local users to bypass permissions and execute files,
as demonstrated by files on an NFSv4 fileserver
[SLE10-SP2, SLE11, openSUSE]

CVE-2009-2406: A kernel stack overflow when mounting eCryptfs
filesystems in parse_tag_11_packet() was fixed. Code execution might
be possible if ecryptfs is in use.
[SLE11, openSUSE]

CVE-2009-2407: A kernel heap overflow when mounting eCryptfs
filesystems in parse_tag_3_packet() was fixed. Code execution might
be possible if ecryptfs is in use.
[SLE11, openSUSE]

(no CVE assigned yet): An information leak from using sigaltstack.
[SLES9, SLES10-SP2, SLE11, openSUSE]

CVE-2009-0676: A memory disclosure via the SO_BSDCOMPAT socket
option
[openSUSE 10.3 only]

CVE-2009-1895: Personality flags on set*id were not cleared
correctly, so ASLR and NULL page protection could be bypassed.
[openSUSE 11.0 only]

CVE-2009-1046: utf-8 console memory corruption that can be used for
local privilege escalation
[openSUSE 11.0 only]

CVE-2008-5033: Oops in video4linux tvaudio
[openSUSE 11.0 only]

CVE-2009-1385: A Integer underflow in the e1000_clean_rx_irq
function in drivers/net/e1000/e1000_main.c in the e1000 driver the
e1000e driver in the Linux kernel, and Intel Wired Ethernet (aka
e1000) before 7.5.5 allows remote attackers to cause a denial of
service (panic) via a crafted frame size.
[openSUSE 11.0 only]

The mmap_min_addr sysctl is now enabled by default to protect
against kernel NULL page exploits.
[SLE11, openSUSE 11.0-11.1]

The -fno-delete-null-pointer-checks compiler option is now used to
build the kernel to avoid gcc optimizing away NULL pointer checks.
Also -fwrapv is now used everywhere.
[SLES9, SLES10-SP2, SLE11, openSUSE]

The kernel update also contains numerous other, non-security
bug fixes. Please refer to the rpm changelog for a detailed list.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:045");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:045.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source-debuginfo", rpm:"kernel-source-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debuginfo", rpm:"kernel-trace-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debugsource", rpm:"kernel-trace-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"aufs-kmp-debug", rpm:"aufs-kmp-debug~cvs20081020_2.6.27.29_0.1~1.32.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"aufs-kmp-trace", rpm:"aufs-kmp-trace~cvs20081020_2.6.27.29_0.1~1.32.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"brocade-bfa-kmp-debug", rpm:"brocade-bfa-kmp-debug~1.1.0.2_2.6.27.29_0.1~1.8.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"brocade-bfa-kmp-trace", rpm:"brocade-bfa-kmp-trace~1.1.0.2_2.6.27.29_0.1~1.8.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.6_2.6.27.29_0.1~1.49.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"dazuko-kmp-trace", rpm:"dazuko-kmp-trace~2.3.6_2.6.27.29_0.1~1.49.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.2.7_2.6.27.29_0.1~1.19.25", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-trace", rpm:"drbd-kmp-trace~8.2.7_2.6.27.29_0.1~1.19.25", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"intel-iamt-heci-kmp-debug", rpm:"intel-iamt-heci-kmp-debug~3.1.0.31_2.6.27.29_0.1~2.40.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"intel-iamt-heci-kmp-trace", rpm:"intel-iamt-heci-kmp-trace~3.1.0.31_2.6.27.29_0.1~2.40.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-debug", rpm:"iscsitarget-kmp-debug~0.4.15_2.6.27.29_0.1~89.11.18", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-trace", rpm:"iscsitarget-kmp-trace~0.4.15_2.6.27.29_0.1~89.11.18", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.4.0pre1_2.6.27.29_0.1~2.1.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kqemu-kmp-trace", rpm:"kqemu-kmp-trace~1.4.0pre1_2.6.27.29_0.1~2.1.12", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kvm-kmp-trace", rpm:"kvm-kmp-trace~78_2.6.27.29_0.1~6.7.4", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"lirc-kmp-trace", rpm:"lirc-kmp-trace~0.8.4_2.6.27.29_0.1~0.1.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-debug", rpm:"ofed-kmp-debug~1.4_2.6.27.29_0.1~21.16.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-trace", rpm:"ofed-kmp-trace~1.4_2.6.27.29_0.1~21.16.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-debug", rpm:"oracleasm-kmp-debug~2.0.5_2.6.27.29_0.1~2.36.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-trace", rpm:"oracleasm-kmp-trace~2.0.5_2.6.27.29_0.1~2.36.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.27.29_0.1~227.56.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-trace", rpm:"pcfclock-kmp-trace~0.44_2.6.27.29_0.1~227.56.14", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"virtualbox-ose-kmp-debug", rpm:"virtualbox-ose-kmp-debug~2.0.6_2.6.27.29_0.1~2.8.55", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"virtualbox-ose-kmp-trace", rpm:"virtualbox-ose-kmp-trace~2.0.6_2.6.27.29_0.1~2.8.55", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"vmware-kmp-debug", rpm:"vmware-kmp-debug~2008.09.03_2.6.27.29_0.1~5.50.37", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"vmware-kmp-trace", rpm:"vmware-kmp-trace~2008.09.03_2.6.27.29_0.1~5.50.37", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source-debuginfo", rpm:"kernel-source-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"acerhk-kmp-debug", rpm:"acerhk-kmp-debug~0.5.35_2.6.25.20_0.5~98.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"acx-kmp-debug", rpm:"acx-kmp-debug~20080210_2.6.25.20_0.5~3.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"appleir-kmp-debug", rpm:"appleir-kmp-debug~1.1_2.6.25.20_0.5~108.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"at76_usb-kmp-debug", rpm:"at76_usb-kmp-debug~0.17_2.6.25.20_0.5~2.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"atl2-kmp-debug", rpm:"atl2-kmp-debug~2.0.4_2.6.25.20_0.5~4.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"aufs-kmp-debug", rpm:"aufs-kmp-debug~cvs20080429_2.6.25.20_0.5~13.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.4.4_2.6.25.20_0.5~42.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.2.6_2.6.25.20_0.5~0.2", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"gspcav-kmp-debug", rpm:"gspcav-kmp-debug~01.00.20_2.6.25.20_0.5~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-debug", rpm:"iscsitarget-kmp-debug~0.4.15_2.6.25.20_0.5~63.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~1.0.3_2.6.25.20_0.5~66.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.3.0pre11_2.6.25.20_0.5~7.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"nouveau-kmp-debug", rpm:"nouveau-kmp-debug~0.10.1.20081112_2.6.25.20_0.5~0.4", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"omnibook-kmp-debug", rpm:"omnibook-kmp-debug~20080313_2.6.25.20_0.5~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"pcc-acpi-kmp-debug", rpm:"pcc-acpi-kmp-debug~0.9_2.6.25.20_0.5~4.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.25.20_0.5~207.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"tpctl-kmp-debug", rpm:"tpctl-kmp-debug~4.17_2.6.25.20_0.5~189.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"uvcvideo-kmp-debug", rpm:"uvcvideo-kmp-debug~r200_2.6.25.20_0.5~2.4", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"virtualbox-ose-kmp-debug", rpm:"virtualbox-ose-kmp-debug~1.5.6_2.6.25.20_0.5~33.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"vmware-kmp-debug", rpm:"vmware-kmp-debug~2008.04.14_2.6.25.20_0.5~21.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"wlan-ng-kmp-debug", rpm:"wlan-ng-kmp-debug~0.2.8_2.6.25.20_0.5~107.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~2.6.3~3.13.46", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump-debugsource", rpm:"kernel-kdump-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-debuginfo", rpm:"kernel-ppc64-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-debugsource", rpm:"kernel-ppc64-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3-debuginfo", rpm:"kernel-ps3-debuginfo~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3-debugsource", rpm:"kernel-ps3-debugsource~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3", rpm:"kernel-ps3~2.6.27.29~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump-debugsource", rpm:"kernel-kdump-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-debuginfo", rpm:"kernel-ppc64-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-debugsource", rpm:"kernel-ppc64-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3-debuginfo", rpm:"kernel-ps3-debuginfo~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3-debugsource", rpm:"kernel-ps3-debugsource~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ps3", rpm:"kernel-ps3~2.6.25.20~0.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.22.19~0.4", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
