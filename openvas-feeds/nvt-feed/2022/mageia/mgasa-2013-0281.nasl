# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0281");
  script_cve_id("CVE-2013-5719", "CVE-2013-5720", "CVE-2013-5721", "CVE-2013-5722");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0281");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0281.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/09/11/1");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.10.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/news/20130910.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-56.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-57.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-58.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-59.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-60.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11214");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2013-0281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ASSA R3 dissector could go into an infinite loop (CVE-2013-5719).
The RTPS dissector could overflow a buffer (CVE-2013-5720).
The MQ dissector could crash (CVE-2013-5721).
The LDAP dissector could crash (CVE-2013-5722).
The Netmon file parser could crash (wpna-sec-2013-60).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark2", rpm:"lib64wireshark2~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark2", rpm:"libwireshark2~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.8.10~1.mga2", rls:"MAGEIA2"))) {
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
