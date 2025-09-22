# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66185");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3700", "CVE-2009-3826");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:293 (squidGuard)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2009\.0|2009\.1|3\.0|4\.0|mes5|2\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in squidGuard:

Buffer overflow in sgLog.c in squidGuard 1.3 and 1.4 allows remote
attackers to cause a denial of service (application hang or loss of
blocking functionality) via a long URL with many / (slash) characters,
related to emergency mode. (CVE-2009-3700).

Multiple buffer overflows in squidGuard 1.4 allow remote attackers
to bypass intended URL blocking via a long URL, related to (1)
the relationship between a certain buffer size in squidGuard and a
certain buffer size in Squid and (2) a redirect URL that contains
information about the originally requested URL (CVE-2009-3826).

squidGuard was upgraded to 1.2.1 for MNF2/CS3/CS4 with additional
upstream security and bug fixes patches applied.

This update fixes these vulnerabilities.

Affected: 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:293");
  script_tag(name:"summary", value:"The remote host is missing an update to squidGuard
announced via advisory MDVSA-2009:293.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.4~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.2.1~0.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.2.1~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.4~0.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.2.1~0.1.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
