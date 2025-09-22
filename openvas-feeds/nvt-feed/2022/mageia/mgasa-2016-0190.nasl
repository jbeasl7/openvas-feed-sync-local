# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0190");
  script_cve_id("CVE-2014-7913");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2016-0190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0190");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0190.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2016/1146.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2016/1244.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2016/1251.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2016/1292.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18422");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcpcd' package(s) announced via the MGASA-2016-0190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The print_option function in dhcp-common.c in dhcpcd through 6.10.2
misinterprets the return value of the snprintf function, which allows
remote DHCP servers to execute arbitrary code or cause a denial of service
(memory corruption) via a crafted message (CVE-2014-7913).

The dhcpcd package has been updated to version 6.11.0 which fixes this
issue and has several other bug fixes and enhancements.");

  script_tag(name:"affected", value:"'dhcpcd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dhcpcd", rpm:"dhcpcd~6.11.0~1.mga5", rls:"MAGEIA5"))) {
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
