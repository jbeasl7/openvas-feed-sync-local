# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0066");
  script_cve_id("CVE-2017-16516", "CVE-2023-33460");
  script_tag(name:"creation_date", value:"2024-03-18 04:11:54 +0000 (Mon, 18 Mar 2024)");
  script_version("2024-03-18T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-03-18 05:06:10 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-22 17:41:30 +0000 (Wed, 22 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2024-0066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0066");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0066.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32072");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3478");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3492");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yajl' package(s) announced via the MGASA-2024-0066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
In the yajl-ruby gem 1.3.0 for Ruby, when a crafted JSON file is
supplied to Yajl::Parser.new.parse, the whole ruby process crashes with
a SIGABRT in the yajl_string_decode function in yajl_encode.c. This
results in the whole ruby process terminating and potentially a denial
of service. (CVE-2017-16516)
There's a memory leak in yajl 2.1.0 with use of yajl_tree_parse
function. which will cause out-of-memory in server and cause crash.
(CVE-2023-33460)");

  script_tag(name:"affected", value:"'yajl' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64yajl-devel", rpm:"lib64yajl-devel~2.1.0~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64yajl2", rpm:"lib64yajl2~2.1.0~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyajl-devel", rpm:"libyajl-devel~2.1.0~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyajl2", rpm:"libyajl2~2.1.0~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yajl", rpm:"yajl~2.1.0~6.1.mga9", rls:"MAGEIA9"))) {
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
