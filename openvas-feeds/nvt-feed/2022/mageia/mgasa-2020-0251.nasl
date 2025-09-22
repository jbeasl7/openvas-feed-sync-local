# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0251");
  script_cve_id("CVE-2020-12105", "CVE-2020-12823");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-14 16:22:17 +0000 (Thu, 14 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0251");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0251.html");
  script_xref(name:"URL", value:"http://www.infradead.org/openconnect/changelog.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26624");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openconnect' package(s) announced via the MGASA-2020-0251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openconnect packages fix security vulnerabilities:

OpenConnect through 8.08 mishandles negative return values from
X509_check_ function calls, which might assist attackers in performing
man-in-the-middle attacks (CVE-2020-12105).

OpenConnect 8.09 has a buffer overflow, causing a denial of service
(application crash) or possibly unspecified other impact, via crafted
certificate data to get_cert_name in gnutls.c (CVE-2020-12823).

The openconnect package has been updated to version 8.10, fixing these
issues and other bugs. See the upstream changelog for details.");

  script_tag(name:"affected", value:"'openconnect' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openconnect-devel", rpm:"lib64openconnect-devel~8.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openconnect5", rpm:"lib64openconnect5~8.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenconnect-devel", rpm:"libopenconnect-devel~8.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenconnect5", rpm:"libopenconnect5~8.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openconnect", rpm:"openconnect~8.10~1.mga7", rls:"MAGEIA7"))) {
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
