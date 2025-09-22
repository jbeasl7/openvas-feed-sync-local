# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0337");
  script_cve_id("CVE-2019-5435", "CVE-2019-5436", "CVE-2019-5481", "CVE-2019-5482");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-17 13:14:20 +0000 (Tue, 17 Sep 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0337");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0337.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23789");
  script_xref(name:"URL", value:"https://curl.haxx.se/changes.html#7_65_0");
  script_xref(name:"URL", value:"https://curl.haxx.se/changes.html#7_66_0");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2019-5435.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2019-5436.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2019-5481.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2019-5482.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3993-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2019-0337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

An integer overflow in curl's URL API results in a buffer overflow
in libcurl 7.62.0 to and including 7.64.1. (CVE-2019-5435)

A heap buffer overflow in the TFTP receiving code allows for DoS or
arbitrary code execution in libcurl versions 7.19.4 through 7.64.1
(CVE-2019-5436).

Double-free vulnerability in the FTP-kerberos code in cURL 7.52.0 to
7.65.3 (CVE-2019-5481).

Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to
7.65.3 (CVE-2019-5482).");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.66.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.66.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.66.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.66.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.66.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.66.0~1.mga7", rls:"MAGEIA7"))) {
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
