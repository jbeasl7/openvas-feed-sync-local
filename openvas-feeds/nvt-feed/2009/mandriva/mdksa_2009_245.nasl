# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64957");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-3289");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 14:56:57 +0000 (Thu, 08 Feb 2024)");
  script_name("Mandrake Security Advisory MDVSA-2009:245 (glib2.0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|mes5)");
  script_tag(name:"insight", value:"A vulnerability was discovered and corrected in glib2.0:

The g_file_copy function in glib 2.0 sets the permissions of a
target file to the permissions of a symbolic link (777), which
allows user-assisted local users to modify files of other users,
as demonstrated by using Nautilus to modify the permissions of the
user home directory (CVE-2009-3289).

This update provides a solution to this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:245");
  script_tag(name:"summary", value:"The remote host is missing an update to glib2.0
announced via advisory MDVSA-2009:245.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.16.2~1.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.18.1~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.20.1~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib2.0-common", rpm:"glib2.0-common~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"glib-gettextize", rpm:"glib-gettextize~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgio2.0_0", rpm:"libgio2.0_0~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0_0", rpm:"libglib2.0_0~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libglib2.0-devel", rpm:"libglib2.0-devel~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gio2.0_0", rpm:"lib64gio2.0_0~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0_0", rpm:"lib64glib2.0_0~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64glib2.0-devel", rpm:"lib64glib2.0-devel~2.18.1~1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
