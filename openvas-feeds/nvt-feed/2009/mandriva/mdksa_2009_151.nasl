# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64393");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0692");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:151 (dhcp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|2\.0)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in ISC DHCP:

Stack-based buffer overflow in the  script_write_params method in
client/dhclient.c in ISC DHCP dhclient 4.1 before 4.1.0p1, 4.0
before 4.0.1p1, 3.1 before 3.1.2p1, 3.0, and 2.0 allows remote DHCP
servers to execute arbitrary code via a crafted subnet-mask option
(CVE-2009-0692).

This update provides fixes for this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:151");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcp
announced via advisory MDVSA-2009:151.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.6~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.7~1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-doc", rpm:"dhcp-doc~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.1.0~5.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0.4~2.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0.4~2.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.4~2.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0.4~2.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0.4~2.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~3.0~1.rc14.0.2.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
