# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66289");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
  script_cve_id("CVE-2009-2903", "CVE-2009-3547", "CVE-2005-4881", "CVE-2009-3612", "CVE-2009-3621", "CVE-2009-3638", "CVE-2009-3726");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");
  script_name("Mandriva Security Advisory MDVSA-2009:301 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"insight", value:"Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:

Memory leak in the appletalk subsystem in the Linux kernel 2.4.x
through 2.4.37.6 and 2.6.x through 2.6.31, when the appletalk and
ipddp modules are loaded but the ipddpN device is not found, allows
remote attackers to cause a denial of service (memory consumption)
via IP-DDP datagrams. (CVE-2009-2903)

Multiple race conditions in fs/pipe.c in the Linux kernel before
2.6.32-rc6 allow local users to cause a denial of service (NULL pointer
dereference and system crash) or gain privileges by attempting to
open an anonymous pipe via a /proc/*/fd/ pathname. (CVE-2009-3547)

The tcf_fill_node function in net/sched/cls_api.c in the netlink
subsystem in the Linux kernel 2.6.x before 2.6.32-rc5, and 2.4.37.6
and earlier, does not initialize a certain tcm__pad2 structure member,
which might allow local users to obtain sensitive information from
kernel memory via unspecified vectors.  NOTE: this issue exists
because of an incomplete fix for CVE-2005-4881. (CVE-2009-3612)

net/unix/af_unix.c in the Linux kernel 2.6.31.4 and earlier allows
local users to cause a denial of service (system hang) by creating an
abstract-namespace AF_UNIX listening socket, performing a shutdown
operation on this socket, and then performing a series of connect
operations to this socket. (CVE-2009-3621)

Integer overflow in the kvm_dev_ioctl_get_supported_cpuid function
in arch/x86/kvm/x86.c in the KVM subsystem in the Linux kernel
before 2.6.31.4 allows local users to have an unspecified impact
via a KVM_GET_SUPPORTED_CPUID request to the kvm_arch_dev_ioctl
function. (CVE-2009-3638)

The nfs4_proc_lock function in fs/nfs/nfs4proc.c in the NFSv4 client in
the Linux kernel before 2.6.31-rc4 allows remote NFS servers to cause
a denial of service (NULL pointer dereference and panic) by sending a
certain response containing incorrect file attributes, which trigger
attempted use of an open file that lacks NFSv4 state. (CVE-2009-3726)

Additionally, it includes the fixes from the stable kernel version
2.6.27.39. It also fixes issues with the bnx2 module in which the
machine could become unresponsive. For details, see the package
changelog.

To update your kernel, please follow the directions linked in the references.");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/security/kernelupdate");

  script_tag(name:"affected", value:"Mandrake Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:301");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory MDVSA-2009:301.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-2.6.27.39-desktop-1mnb", rpm:"drm-experimental-kernel-2.6.27.39-desktop-1mnb~2.3.0~2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-2.6.27.39-desktop586-1mnb", rpm:"drm-experimental-kernel-2.6.27.39-desktop586-1mnb~2.3.0~2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-2.6.27.39-server-1mnb", rpm:"drm-experimental-kernel-2.6.27.39-server-1mnb~2.3.0~2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-desktop586-latest", rpm:"drm-experimental-kernel-desktop586-latest~2.3.0~1.20091119.2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-desktop-latest", rpm:"drm-experimental-kernel-desktop-latest~2.3.0~1.20091119.2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"drm-experimental-kernel-server-latest", rpm:"drm-experimental-kernel-server-latest~2.3.0~1.20091119.2.20080912.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.27.39-desktop-1mnb", rpm:"fglrx-kernel-2.6.27.39-desktop-1mnb~8.522~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.27.39-desktop586-1mnb", rpm:"fglrx-kernel-2.6.27.39-desktop586-1mnb~8.522~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.27.39-server-1mnb", rpm:"fglrx-kernel-2.6.27.39-server-1mnb~8.522~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~8.522~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~8.522~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~8.522~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-2.6.27.39-desktop-1mnb", rpm:"iscsitarget-kernel-2.6.27.39-desktop-1mnb~0.4.16~4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-2.6.27.39-desktop586-1mnb", rpm:"iscsitarget-kernel-2.6.27.39-desktop586-1mnb~0.4.16~4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-2.6.27.39-server-1mnb", rpm:"iscsitarget-kernel-2.6.27.39-server-1mnb~0.4.16~4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-desktop586-latest", rpm:"iscsitarget-kernel-desktop586-latest~0.4.16~1.20091119.4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-desktop-latest", rpm:"iscsitarget-kernel-desktop-latest~0.4.16~1.20091119.4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"iscsitarget-kernel-server-latest", rpm:"iscsitarget-kernel-server-latest~0.4.16~1.20091119.4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-2.6.27.39-1mnb", rpm:"kernel-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-2.6.27.39-1mnb", rpm:"kernel-desktop-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-2.6.27.39-1mnb", rpm:"kernel-desktop586-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-2.6.27.39-1mnb", rpm:"kernel-desktop586-devel-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-2.6.27.39-1mnb", rpm:"kernel-desktop-devel-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-2.6.27.39-1mnb", rpm:"kernel-server-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-2.6.27.39-1mnb", rpm:"kernel-server-devel-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-2.6.27.39-1mnb", rpm:"kernel-source-2.6.27.39-1mnb~1~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.27.39~1mnb2", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.27.39-desktop-1mnb", rpm:"kqemu-kernel-2.6.27.39-desktop-1mnb~1.4.0pre1~0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.27.39-desktop586-1mnb", rpm:"kqemu-kernel-2.6.27.39-desktop586-1mnb~1.4.0pre1~0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.27.39-server-1mnb", rpm:"kqemu-kernel-2.6.27.39-server-1mnb~1.4.0pre1~0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop586-latest", rpm:"kqemu-kernel-desktop586-latest~1.4.0pre1~1.20091119.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop-latest", rpm:"kqemu-kernel-desktop-latest~1.4.0pre1~1.20091119.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-server-latest", rpm:"kqemu-kernel-server-latest~1.4.0pre1~1.20091119.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.27.39-desktop-1mnb", rpm:"libafs-kernel-2.6.27.39-desktop-1mnb~1.4.7~5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.27.39-desktop586-1mnb", rpm:"libafs-kernel-2.6.27.39-desktop586-1mnb~1.4.7~5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.27.39-server-1mnb", rpm:"libafs-kernel-2.6.27.39-server-1mnb~1.4.7~5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-desktop586-latest", rpm:"libafs-kernel-desktop586-latest~1.4.7~1.20091119.5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-desktop-latest", rpm:"libafs-kernel-desktop-latest~1.4.7~1.20091119.5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-server-latest", rpm:"libafs-kernel-server-latest~1.4.7~1.20091119.5.2mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.27.39-desktop-1mnb", rpm:"madwifi-kernel-2.6.27.39-desktop-1mnb~0.9.4~3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.27.39-desktop586-1mnb", rpm:"madwifi-kernel-2.6.27.39-desktop586-1mnb~0.9.4~3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.27.39-server-1mnb", rpm:"madwifi-kernel-2.6.27.39-server-1mnb~0.9.4~3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop586-latest", rpm:"madwifi-kernel-desktop586-latest~0.9.4~1.20091119.3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop-latest", rpm:"madwifi-kernel-desktop-latest~0.9.4~1.20091119.3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-server-latest", rpm:"madwifi-kernel-server-latest~0.9.4~1.20091119.3.r3835mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.27.39-desktop-1mnb", rpm:"nvidia173-kernel-2.6.27.39-desktop-1mnb~173.14.12~4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.27.39-desktop586-1mnb", rpm:"nvidia173-kernel-2.6.27.39-desktop586-1mnb~173.14.12~4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.12~1.20091119.4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.12~1.20091119.4mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-2.6.27.39-desktop-1mnb", rpm:"nvidia71xx-kernel-2.6.27.39-desktop-1mnb~71.86.06~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-2.6.27.39-desktop586-1mnb", rpm:"nvidia71xx-kernel-2.6.27.39-desktop586-1mnb~71.86.06~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-2.6.27.39-server-1mnb", rpm:"nvidia71xx-kernel-2.6.27.39-server-1mnb~71.86.06~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-desktop586-latest", rpm:"nvidia71xx-kernel-desktop586-latest~71.86.06~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-desktop-latest", rpm:"nvidia71xx-kernel-desktop-latest~71.86.06~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-server-latest", rpm:"nvidia71xx-kernel-server-latest~71.86.06~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.27.39-desktop-1mnb", rpm:"nvidia96xx-kernel-2.6.27.39-desktop-1mnb~96.43.07~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.27.39-desktop586-1mnb", rpm:"nvidia96xx-kernel-2.6.27.39-desktop586-1mnb~96.43.07~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.27.39-server-1mnb", rpm:"nvidia96xx-kernel-2.6.27.39-server-1mnb~96.43.07~5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop586-latest", rpm:"nvidia96xx-kernel-desktop586-latest~96.43.07~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop-latest", rpm:"nvidia96xx-kernel-desktop-latest~96.43.07~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-server-latest", rpm:"nvidia96xx-kernel-server-latest~96.43.07~1.20091119.5mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.27.39-desktop-1mnb", rpm:"nvidia-current-kernel-2.6.27.39-desktop-1mnb~177.70~2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.27.39-desktop586-1mnb", rpm:"nvidia-current-kernel-2.6.27.39-desktop586-1mnb~177.70~2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.27.39-server-1mnb", rpm:"nvidia-current-kernel-2.6.27.39-server-1mnb~177.70~2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~177.70~1.20091119.2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~177.70~1.20091119.2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~177.70~1.20091119.2.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.27.39-desktop-1mnb", rpm:"vpnclient-kernel-2.6.27.39-desktop-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.27.39-desktop586-1mnb", rpm:"vpnclient-kernel-2.6.27.39-desktop586-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.27.39-server-1mnb", rpm:"vpnclient-kernel-2.6.27.39-server-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop586-latest", rpm:"vpnclient-kernel-desktop586-latest~4.8.01.0640~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop-latest", rpm:"vpnclient-kernel-desktop-latest~4.8.01.0640~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-server-latest", rpm:"vpnclient-kernel-server-latest~4.8.01.0640~1.20091119.3mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.27.39-desktop-1mnb", rpm:"libafs-kernel-2.6.27.39-desktop-1mnb~1.4.7~5.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.27.39-server-1mnb", rpm:"libafs-kernel-2.6.27.39-server-1mnb~1.4.7~5.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-desktop-latest", rpm:"libafs-kernel-desktop-latest~1.4.7~1.20091119.5.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-server-latest", rpm:"libafs-kernel-server-latest~1.4.7~1.20091119.5.1mdv2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
