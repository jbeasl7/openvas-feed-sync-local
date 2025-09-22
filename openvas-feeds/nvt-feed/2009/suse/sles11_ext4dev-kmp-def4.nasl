# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=551348");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=549567");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=441062");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=547357");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=549751");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=556532");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=551942");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=544760");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=554122");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=547137");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=540349");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=539878");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=548070");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=536467");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=548071");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=551142");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=544779");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=522790");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=548807");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=550648");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=519820");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=552775");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=531716");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=524222");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=528427");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=524683");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=552602");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=523487");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=539010");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=472410");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=549748");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=542505");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=548101");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=541648");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=540997");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=556864");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=548074");
  script_oid("1.3.6.1.4.1.25623.1.0.66352");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2009-3547", "CVE-2009-2910", "CVE-2009-2903", "CVE-2009-3621", "CVE-2009-3612", "CVE-2005-4881", "CVE-2009-3620", "CVE-2009-3726", "CVE-2009-3286");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-03 17:13:00 +0000 (Fri, 03 Nov 2023)");
  script_name("SLES11: Security update for Linux kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages are affected:

    ext4dev-kmp-default

    ext4dev-kmp-pae

    ext4dev-kmp-vmi

    ext4dev-kmp-xen

    kernel-default

    kernel-default-base

    kernel-pae

    kernel-pae-base

    kernel-source

    kernel-syms

    kernel-vmi

    kernel-vmi-base

    kernel-xen

    kernel-xen-base

More details may also be found by searching for the SuSE
Enterprise Server 11 patch database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.27.39_0.3~7.1.22", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.27.39_0.3~7.1.22", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-vmi", rpm:"ext4dev-kmp-vmi~0_2.6.27.39_0.3~7.1.22", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.27.39_0.3~7.1.22", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.39~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
