# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66020");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
  script_cve_id("CVE-2008-1502");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mandrake Security Advisory MDVSA-2009:265 (egroupware)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_3\.0");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in egroupware:

The _bad_protocol_once function in phpgwapi/inc/class.kses.inc.php
in KSES, as used in eGroupWare before 1.4.003, Moodle before 1.8.5,
and other products, allows remote attackers to bypass HTML filtering
and conduct cross-site scripting (XSS) attacks via a string containing
crafted URL protocols (CVE-2008-1502).

This update fixes this vulnerability.

Affected: Corporate 3.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:265");
  script_tag(name:"summary", value:"The remote host is missing an update to egroupware
announced via advisory MDVSA-2009:265.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"egroupware", rpm:"egroupware~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-addressbook", rpm:"egroupware-addressbook~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-backup", rpm:"egroupware-backup~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-bookmarks", rpm:"egroupware-bookmarks~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-calendar", rpm:"egroupware-calendar~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-comic", rpm:"egroupware-comic~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-developer_tools", rpm:"egroupware-developer_tools~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-email", rpm:"egroupware-email~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-emailadmin", rpm:"egroupware-emailadmin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-etemplate", rpm:"egroupware-etemplate~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-felamimail", rpm:"egroupware-felamimail~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-filemanager", rpm:"egroupware-filemanager~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-forum", rpm:"egroupware-forum~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-ftp", rpm:"egroupware-ftp~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-fudforum", rpm:"egroupware-fudforum~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-headlines", rpm:"egroupware-headlines~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-infolog", rpm:"egroupware-infolog~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-jinn", rpm:"egroupware-jinn~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-messenger", rpm:"egroupware-messenger~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-news_admin", rpm:"egroupware-news_admin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpbrain", rpm:"egroupware-phpbrain~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpldapadmin", rpm:"egroupware-phpldapadmin~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-phpsysinfo", rpm:"egroupware-phpsysinfo~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-polls", rpm:"egroupware-polls~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-projects", rpm:"egroupware-projects~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-registration", rpm:"egroupware-registration~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-sitemgr", rpm:"egroupware-sitemgr~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-skel", rpm:"egroupware-skel~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-stocks", rpm:"egroupware-stocks~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-tts", rpm:"egroupware-tts~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"egroupware-wiki", rpm:"egroupware-wiki~1.0~0.RC3.1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
