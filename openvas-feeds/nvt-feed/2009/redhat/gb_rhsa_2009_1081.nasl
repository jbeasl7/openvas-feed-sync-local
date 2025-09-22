# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64068");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1338", "CVE-2009-1439");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1081");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to kernel-rt announced in
advisory RHSA-2009:1081.

These updated packages fix the following security issues:

  * a buffer overflow flaw was found in the CIFSTCon() function of the Linux
kernel Common Internet File System (CIFS) implementation. When mounting a
CIFS share, a malicious server could send an overly-long string to the
client, possibly leading to a denial of service or privilege escalation on
the client mounting the CIFS share. (CVE-2009-1439, Important)

  * the Linux kernel Network File System daemon (nfsd) implementation did not
drop the CAP_MKNOD capability when handling requests from local,
unprivileged users. This flaw could possibly lead to an information leak or
privilege escalation. (CVE-2009-1072, Moderate)

  * a deficiency was found in the Linux kernel signals implementation. The
kill_something_info() function did not check if a process was outside the
caller's namespace before sending the kill signal, making it possible to
kill processes in all process ID (PID) namespaces, breaking PID namespace
isolation. (CVE-2009-1338, Moderate)

  * a flaw was found in the AGPGART driver. The agp_generic_alloc_page() and
agp_generic_alloc_pages() functions did not zero out the memory pages they
allocate, which may later be available to user-space processes. This flaw
could possibly lead to an information leak. (CVE-2009-1192, Low)

All Red Hat Enterprise MRG users should upgrade to these updated packages,
which contain backported patches to resolve these issues. Note: The system
must be rebooted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1081.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug", rpm:"kernel-rt-debug~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-debuginfo", rpm:"kernel-rt-debug-debuginfo~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-devel", rpm:"kernel-rt-debug-devel~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo-common", rpm:"kernel-rt-debuginfo-common~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace", rpm:"kernel-rt-trace~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-debuginfo", rpm:"kernel-rt-trace-debuginfo~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-devel", rpm:"kernel-rt-trace-devel~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla", rpm:"kernel-rt-vanilla~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-debuginfo", rpm:"kernel-rt-vanilla-debuginfo~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-devel", rpm:"kernel-rt-vanilla-devel~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~2.6.24.7~117.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
