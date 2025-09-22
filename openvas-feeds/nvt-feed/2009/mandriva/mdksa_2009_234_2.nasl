# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66413");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-3051", "CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3163");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:234-2 (silc-toolkit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in silc-toolkit:

Multiple format string vulnerabilities in lib/silcclient/client_entry.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10, and
SILC Client before 1.1.8, allow remote attackers to execute arbitrary
code via format string specifiers in a nickname field, related to the
(1) silc_client_add_client, (2) silc_client_update_client, and (3)
silc_client_nickname_format functions (CVE-2009-3051).

The silc_asn1_encoder function in lib/silcasn1/silcasn1_encode.c in
Secure Internet Live Conferencing (SILC) Toolkit before 1.1.8 allows
remote attackers to overwrite a stack location and possibly execute
arbitrary code via a crafted OID value, related to incorrect use of
a %lu format string (CVE-2008-7159).

The silc_http_server_parse function in lib/silchttp/silchttpserver.c in
the internal HTTP server in silcd in Secure Internet Live Conferencing
(SILC) Toolkit before 1.1.9 allows remote attackers to overwrite
a stack location and possibly execute arbitrary code via a crafted
Content-Length header, related to incorrect use of a %lu format string
(CVE-2008-7160).

Multiple format string vulnerabilities in lib/silcclient/command.c
in Secure Internet Live Conferencing (SILC) Toolkit before 1.1.10,
and SILC Client 1.1.8 and earlier, allow remote attackers to execute
arbitrary code via format string specifiers in a channel name, related
to (1) silc_client_command_topic, (2) silc_client_command_kick,
(3) silc_client_command_leave, and (4) silc_client_command_users
(CVE-2009-3163).

This update provides a solution to these vulnerabilities.

Update:

Packages for MES5 was not provided previously, this update addresses
this problem.

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:234-2");
  script_tag(name:"summary", value:"The remote host is missing an update to silc-toolkit
announced via advisory MDVSA-2009:234-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libsilc-1.1_2", rpm:"libsilc-1.1_2~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilcclient-1.1_2", rpm:"libsilcclient-1.1_2~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit", rpm:"silc-toolkit~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"silc-toolkit-devel", rpm:"silc-toolkit-devel~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silc-1.1_2", rpm:"lib64silc-1.1_2~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64silcclient-1.1_2", rpm:"lib64silcclient-1.1_2~1.1.2~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
