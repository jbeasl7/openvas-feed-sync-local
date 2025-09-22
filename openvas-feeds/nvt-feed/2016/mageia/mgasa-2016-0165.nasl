# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131287");
  script_cve_id("CVE-2016-4049");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:50 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-24 17:12:16 +0000 (Tue, 24 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0165");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0165.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/04/27/7");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18280");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the MGASA-2016-0165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated quagga packages fix security vulnerability:

A denial of dervice vulnerability have been found in BGP daemon
from Quagga routing software (bgpd): if the following conditions are
satisfied:

 - regular dumping is enabled
 - bgpd instance has many BGP peers

then BGP message packets that are big enough cause bgpd to crash.
The situation when the conditions above are satisfied is quite common.
Moreover, it is easy to craft a packet which is much 'bigger' than a
typical packet, and hence such crafted packet can much more likely cause
the crash (CVE-2016-4049).");

  script_tag(name:"affected", value:"'quagga' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64quagga-devel", rpm:"lib64quagga-devel~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quagga0", rpm:"lib64quagga0~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga-devel", rpm:"libquagga-devel~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga0", rpm:"libquagga0~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.22.4~4.2.mga5", rls:"MAGEIA5"))) {
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
