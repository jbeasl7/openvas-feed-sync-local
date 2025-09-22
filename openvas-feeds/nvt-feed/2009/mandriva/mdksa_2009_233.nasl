# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64906");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
  script_cve_id("CVE-2009-2692");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");
  script_name("Mandrake Security Advisory MDVSA-2009:233 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"A vulnerability was discovered and corrected in the Linux 2.6 kernel:

The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4,
does not initialize all function pointers for socket operations
in proto_ops structures, which allows local users to trigger a NULL
pointer dereference and gain privileges by using mmap to map page zero,
placing arbitrary code on this page, and then invoking an unavailable
operation, as demonstrated by the sendpage operation on a PF_PPPOX
socket. (CVE-2009-2692)

To update your kernel, please follow the directions linked in the references.");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/security/kernelupdate");

  script_tag(name:"affected", value:"Mandrake 2008.1, Corporate 3.0, Corporate 4.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:233");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory MDVSA-2009:233.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-2.6.24.7-3mnb", rpm:"kernel-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-2.6.24.7-3mnb", rpm:"kernel-desktop-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-2.6.24.7-3mnb", rpm:"kernel-desktop586-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-2.6.24.7-3mnb", rpm:"kernel-desktop586-devel-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-2.6.24.7-3mnb", rpm:"kernel-desktop-devel-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-laptop-2.6.24.7-3mnb", rpm:"kernel-laptop-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-laptop-devel-2.6.24.7-3mnb", rpm:"kernel-laptop-devel-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-laptop-devel-latest", rpm:"kernel-laptop-devel-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-laptop-latest", rpm:"kernel-laptop-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-2.6.24.7-3mnb", rpm:"kernel-server-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-2.6.24.7-3mnb", rpm:"kernel-server-devel-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-2.6.24.7-3mnb", rpm:"kernel-source-2.6.24.7-3mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.24.7~3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-2.6.3.41mdk", rpm:"kernel-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-BOOT-2.6.3.41mdk", rpm:"kernel-BOOT-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.3~41mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-enterprise-2.6.3.41mdk", rpm:"kernel-enterprise-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-i686-up-4GB-2.6.3.41mdk", rpm:"kernel-i686-up-4GB-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-p3-smp-64GB-2.6.3.41mdk", rpm:"kernel-p3-smp-64GB-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-secure-2.6.3.41mdk", rpm:"kernel-secure-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-2.6.3.41mdk", rpm:"kernel-smp-2.6.3.41mdk~1~1mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.3~41mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.3~41mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-2.6.12.41mdk", rpm:"kernel-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-BOOT-2.6.12.41mdk", rpm:"kernel-BOOT-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc-2.6.12.41mdk", rpm:"kernel-doc-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-i586-up-1GB-2.6.12.41mdk", rpm:"kernel-i586-up-1GB-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-i686-up-4GB-2.6.12.41mdk", rpm:"kernel-i686-up-4GB-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-2.6.12.41mdk", rpm:"kernel-smp-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-2.6.12.41mdk", rpm:"kernel-source-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-stripped-2.6.12.41mdk", rpm:"kernel-source-stripped-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xbox-2.6.12.41mdk", rpm:"kernel-xbox-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen0-2.6.12.41mdk", rpm:"kernel-xen0-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenU-2.6.12.41mdk", rpm:"kernel-xenU-2.6.12.41mdk~1~1mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-2.6.3.41mdk", rpm:"kernel-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-BOOT-2.6.3.41mdk", rpm:"kernel-BOOT-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.3~41mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-enterprise-2.6.3.41mdk", rpm:"kernel-enterprise-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-i686-up-4GB-2.6.3.41mdk", rpm:"kernel-i686-up-4GB-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-p3-smp-64GB-2.6.3.41mdk", rpm:"kernel-p3-smp-64GB-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-secure-2.6.3.41mdk", rpm:"kernel-secure-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp-2.6.3.41mdk", rpm:"kernel-smp-2.6.3.41mdk~1~1mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.3~41mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.3~41mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
