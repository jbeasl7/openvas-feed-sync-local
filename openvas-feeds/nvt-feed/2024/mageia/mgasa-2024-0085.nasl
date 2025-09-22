# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0085");
  script_cve_id("CVE-2023-30570", "CVE-2023-38710", "CVE-2023-38711", "CVE-2023-38712");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-03 04:12:44 +0000 (Sat, 03 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0085)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0085");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0085.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:2120");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31865");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2023-30570/CVE-2023-30570.txt");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2023-38710");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2023-38711");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2023-38712");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/APPXJHIVUBS4I2AVIB6C36ED6XNUYVC2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the MGASA-2024-0085 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package fixes security vulnerabilities:
pluto in Libreswan before 4.11 allows a denial of service (responder SPI
mishandling and daemon crash) via unauthenticated IKEv1 Aggressive Mode
packets. (CVE-2023-30570)
An issue was discovered in Libreswan before 4.12. When an IKEv2 Child SA
REKEY packet contains an invalid IPsec protocol ID number of 0 or 1, an
error notify INVALID_SPI is sent back. The notify payload's protocol ID
is copied from the incoming packet, but the code that verifies outgoing
packets fails an assertion that the protocol ID must be ESP (2) or AH(3)
and causes the pluto daemon to crash and restart. (CVE-2023-38710)
An issue was discovered in Libreswan before 4.12. When an IKEv1 Quick
Mode connection configured with ID_IPV4_ADDR or ID_IPV6_ADDR receives an
IDcr payload with ID_FQDN, a NULL pointer dereference causes a crash and
restart of the pluto daemon. (CVE-2023-38711)
An issue was discovered in Libreswan 3.x and 4.x before 4.12. When an
IKEv1 ISAKMP SA Informational Exchange packet contains a Delete/Notify
payload followed by further Notifies that act on the ISAKMP SA, such as
a duplicated Delete/Notify message, a NULL pointer dereference on the
deleted state causes the pluto daemon to crash and restart.
(CVE-2023-38712)");

  script_tag(name:"affected", value:"'libreswan' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~4.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
