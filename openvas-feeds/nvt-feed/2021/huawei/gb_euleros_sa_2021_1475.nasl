# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1475");
  script_cve_id("CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314");
  script_tag(name:"creation_date", value:"2021-03-05 07:07:40 +0000 (Fri, 05 Mar 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 13:27:35 +0000 (Tue, 04 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for gdk-pixbuf2 (EulerOS-SA-2021-1475)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1475");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1475");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gdk-pixbuf2' package(s) announced via the EulerOS-SA-2021-1475 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in io-ico.c in gdk-pixbuf allows context-dependent attackers to cause a denial of service (segmentation fault and application crash) via a crafted image entry offset in an ICO file, which triggers an out-of-bounds read, related to compiler optimizations.(CVE-2017-6312)

Integer underflow in the load_resources function in io-icns.c in gdk-pixbuf allows context-dependent attackers to cause a denial of service (out-of-bounds read and program crash) via a crafted image entry size in an ICO file.(CVE-2017-6313)

The make_available_at_least function in io-tiff.c in gdk-pixbuf allows context-dependent attackers to cause a denial of service (infinite loop) via a large TIFF file.(CVE-2017-6314)");

  script_tag(name:"affected", value:"'gdk-pixbuf2' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2", rpm:"gdk-pixbuf2~2.36.5~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2-devel", rpm:"gdk-pixbuf2-devel~2.36.5~1.h6.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
