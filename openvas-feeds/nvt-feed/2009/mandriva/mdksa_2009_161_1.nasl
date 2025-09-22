# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64605");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2621", "CVE-2009-2622");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:161-1 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|mes5)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in squid:

Due to incorrect buffer limits and related bound checks Squid is
vulnerable to a denial of service attack when processing specially
crafted requests or responses (CVE-2009-2621).

Due to incorrect data validation Squid is vulnerable to a denial
of service attack when processing specially crafted responses
(CVE-2009-2622).

This update provides fixes for these vulnerabilities.

Update:

Additional upstream security patches were applied:

Debug warnings fills up the logs.

Upstream Bug 2728: regression: assertion failed: http.cc:705: !eof

Affected: 2008.1, 2009.0, 2009.1, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:161-1");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2009_2.txt");
  script_tag(name:"summary", value:"The remote host is missing an update to squid
announced via advisory MDVSA-2009:161-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.0~1.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.0~1.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.0~8.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.0~8.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.0~14.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.0~14.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.0~8.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~3.0~8.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
