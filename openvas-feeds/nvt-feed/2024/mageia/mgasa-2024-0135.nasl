# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0135");
  script_cve_id("CVE-2024-28182");
  script_tag(name:"creation_date", value:"2024-04-17 04:14:03 +0000 (Wed, 17 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0135");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0135.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33087");
  script_xref(name:"URL", value:"https://github.com/nghttp2/nghttp2/security/advisories/GHSA-x6x3-gv8h-m57q");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2' package(s) announced via the MGASA-2024-0135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nghttp2 library keeps reading the unbounded number of HTTP/2
CONTINUATION frames even after a stream is reset to keep HPACK context
in sync. This causes excessive CPU usage to decode HPACK stream.
This update fixes the issue.
This is the latest release, which will bring some more fixes and
improvements.");

  script_tag(name:"affected", value:"'nghttp2' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2-devel", rpm:"lib64nghttp2-devel~1.61.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2_14", rpm:"lib64nghttp2_14~1.61.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.61.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_14", rpm:"libnghttp2_14~1.61.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.61.0~1.mga9", rls:"MAGEIA9"))) {
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
