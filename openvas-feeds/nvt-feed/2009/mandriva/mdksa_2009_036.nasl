# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63373");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2007-4965", "CVE-2008-1679", "CVE-2008-4864", "CVE-2008-5031", "CVE-2008-2315");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:036 (python)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(3\.0|2\.0)");
  script_tag(name:"insight", value:"Multiple integer overflows in imageop.c in the imageop module in
Python 1.5.2 through 2.5.1 allow context-dependent attackers to
break out of the Python VM and execute arbitrary code via large
integer values in certain arguments to the crop function, leading to
a buffer overflow, a different vulnerability than CVE-2007-4965 and
CVE-2008-1679. (CVE-2008-4864)

Multiple integer overflows in Python 2.5.2 and earlier allow
context-dependent attackers to have an unknown impact via vectors
related to the (1) stringobject, (2) unicodeobject, (3) bufferobject,
(4) longobject, (5) tupleobject, (6) stropmodule, (7) gcmodule, and
(8) mmapmodule modules. NOTE: The expandtabs integer overflows in
stringobject and unicodeobject in 2.5.2 are covered by CVE-2008-5031.

Multiple integer overflows in Python 2.2.3 through 2.5.1, and 2.6,
allow context-dependent attackers to have an unknown impact via
a large integer value in the tabsize argument to the expandtabs
method, as implemented by (1) the string_expandtabs function in
Objects/stringobject.c and (2) the unicode_expandtabs function in
Objects/unicodeobject.c. NOTE: this vulnerability reportedly exists
because of an incomplete fix for CVE-2008-2315. (CVE-2008-5031)

The updated Python packages have been patched to correct these issues.

Affected: Corporate 3.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:036");
  script_tag(name:"summary", value:"The remote host is missing an update to python
announced via advisory MDVSA-2009:036.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libpython2.3", rpm:"libpython2.3~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3-devel", rpm:"libpython2.3-devel~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64python2.3", rpm:"lib64python2.3~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64python2.3-devel", rpm:"lib64python2.3-devel~2.3.7~0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3", rpm:"libpython2.3~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpython2.3-devel", rpm:"libpython2.3-devel~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python", rpm:"python~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.3.7~0.2.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
