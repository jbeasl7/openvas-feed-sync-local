# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63250");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-0598", "CVE-2008-3528", "CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-5029");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0009");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to the kernel announced in
advisory RHSA-2009:0009.

These updated packages address the following security issues:

  * Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
64-bit emulation. This could allow a local, unprivileged user to prepare
and run a specially-crafted binary which would use this deficiency to leak
uninitialized and potentially sensitive data. (CVE-2008-0598, Important)

  * Olaf Kirch reported a flaw in the i915 kernel driver that only affects
the Intel G33 series and newer. This flaw could, potentially, lead to local
privilege escalation. (CVE-2008-3831, Important)

  * Miklos Szeredi reported a missing check for files opened with O_APPEND in
sys_splice(). This could allow a local, unprivileged user to bypass the
append-only file restrictions. (CVE-2008-4554, Important)

  * a deficiency was found in the Linux kernel Stream Control Transmission
Protocol (SCTP) implementation. This could lead to a possible denial of
service if one end of a SCTP connection did not support the AUTH extension.
(CVE-2008-4576, Important)

  * Wei Yongjun reported a flaw in the Linux kernel SCTP implementation. In
certain code paths, sctp_sf_violation_paramlen() could be called with a
wrong parameter data type. This could lead to a possible denial of service.
(CVE-2008-4618, Important)

  * when fput() was called to close a socket, the __scm_destroy() function in
the Linux kernel could make indirect recursive calls to itself. This could,
potentially, lead to a denial of service issue. (CVE-2008-5029, Important)

  * the ext2 and ext3 filesystem code failed to properly handle corrupted
data structures, leading to a possible local denial of service issue when
read or write operations were performed. (CVE-2008-3528, Low)

All Red Hat Enterprise MRG users should install this update which addresses
these vulnerabilities and fixes these bugs.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0009.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");
  script_xref(name:"URL", value:"http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug", rpm:"kernel-rt-debug~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-debuginfo", rpm:"kernel-rt-debug-debuginfo~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-devel", rpm:"kernel-rt-debug-devel~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo-common", rpm:"kernel-rt-debuginfo-common~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace", rpm:"kernel-rt-trace~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-debuginfo", rpm:"kernel-rt-trace-debuginfo~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-devel", rpm:"kernel-rt-trace-devel~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla", rpm:"kernel-rt-vanilla~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-debuginfo", rpm:"kernel-rt-vanilla-debuginfo~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-devel", rpm:"kernel-rt-vanilla-devel~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~2.6.24.7~93.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
