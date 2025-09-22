# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131196");
  script_cve_id("CVE-2016-1503", "CVE-2016-1504");
  script_tag(name:"creation_date", value:"2016-01-25 05:27:44 +0000 (Mon, 25 Jan 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-20 17:43:58 +0000 (Wed, 20 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0034.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/01/07/4");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1001.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1004.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1012.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1018.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1058.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1089.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1093.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2015/1129.html");
  script_xref(name:"URL", value:"http://roy.marples.name/archives/dhcpcd-discuss/2016/1143.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17462");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcpcd' package(s) announced via the MGASA-2016-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible heap overflow in dhcpcd before 6.10.0 caused by malformed dhcp
responses due to incorrect option length values (CVE-2016-1503).

Possible invalid read in dhcpcd before 6.10.0 caused by malformed dhcp
responses can lead to a crash (CVE-2016-1504).

The dhcpcd package has been updated to version 6.10.0 which fixes these
issues and has several other bug fixes and enhancements.");

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

  if(!isnull(res = isrpmvuln(pkg:"dhcpcd", rpm:"dhcpcd~6.10.0~1.mga5", rls:"MAGEIA5"))) {
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
