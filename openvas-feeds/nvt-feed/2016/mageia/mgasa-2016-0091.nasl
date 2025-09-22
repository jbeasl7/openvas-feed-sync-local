# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131246");
  script_cve_id("CVE-2016-2522", "CVE-2016-2523", "CVE-2016-2524", "CVE-2016-2525", "CVE-2016-2526", "CVE-2016-2527", "CVE-2016-2528", "CVE-2016-2529", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532");
  script_tag(name:"creation_date", value:"2016-03-03 12:39:16 +0000 (Thu, 03 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-02 15:27:18 +0000 (Wed, 02 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0091)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0091");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0091.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17848");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.2.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20160226.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-05.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-07.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-08.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-11.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-14.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-15.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-16.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-17.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-18.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2016-0091 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated wireshark packages fix security vulnerabilities:

ASN.1 BER dissector crash (CVE-2016-2522).

DNP dissector infinite loop (CVE-2016-2523).

X.509AF dissector crash (CVE-2016-2524).

HTTP/2 dissector crash (CVE-2016-2525).

HiQnet dissector crash (CVE-2016-2526).

3GPP TS 32.423 Trace file parser crash (CVE-2016-2527).

LBMC dissector crash (CVE-2016-2528).

iSeries file parser crash (CVE-2016-2529).

RSL dissector crash (CVE-2016-2530, CVE-2016-2531).

LLRP dissector crash (CVE-2016-2532).

The wireshark package has been updated to version 2.0.2, fixing these issues as
well as other dissector crashes, a dissector loop issue, another file parser
crash, and several other bugs. See the upstream release notes for details.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark6", rpm:"lib64wireshark6~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap5", rpm:"lib64wiretap5~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil6", rpm:"lib64wsutil6~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark6", rpm:"libwireshark6~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap5", rpm:"libwiretap5~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil6", rpm:"libwsutil6~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.0.2~1.mga5", rls:"MAGEIA5"))) {
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
