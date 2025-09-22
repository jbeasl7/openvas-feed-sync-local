# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66030");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
  script_cve_id("CVE-2009-2185");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:273 (strongswan)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2\.0");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in strongswan:

The ASN.1 parser (pluto/asn1.c, libstrongswan/asn1/asn1.c,
libstrongswan/asn1/asn1_parser.c) in (a) strongSwan 2.8 before 2.8.10,
4.2 before 4.2.16, and 4.3 before 4.3.2, and (b) openSwan 2.6 before
2.6.22 and 2.4 before 2.4.15 allows remote attackers to cause a denial
of service (pluto IKE daemon crash) via an X.509 certificate with (1)
crafted Relative Distinguished Names (RDNs), (2) a crafted UTCTIME
string, or (3) a crafted GENERALIZEDTIME string (CVE-2009-2185).

This update fixes this vulnerability.

Affected: Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:273");
  script_tag(name:"summary", value:"The remote host is missing an update to strongswan
announced via advisory MDVSA-2009:273.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~2.0.2~1.1.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
