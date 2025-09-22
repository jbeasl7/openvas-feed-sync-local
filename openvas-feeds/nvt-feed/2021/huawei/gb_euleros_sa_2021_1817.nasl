# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1817");
  script_cve_id("CVE-2019-5068");
  script_tag(name:"creation_date", value:"2021-05-03 06:22:14 +0000 (Mon, 03 May 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 20:32:51 +0000 (Tue, 12 Nov 2019)");

  script_name("Huawei EulerOS: Security Advisory for mesa (EulerOS-SA-2021-1817)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1817");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1817");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mesa' package(s) announced via the EulerOS-SA-2021-1817 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable shared memory permissions vulnerability exists in the functionality of X11 Mesa 3D Graphics Library 19.1.2. An attacker can access the shared memory without any specific permissions to trigger this vulnerability.(CVE-2019-5068)");

  script_tag(name:"affected", value:"'mesa' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mesa-dri-drivers", rpm:"mesa-dri-drivers~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-filesystem", rpm:"mesa-filesystem~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libEGL", rpm:"mesa-libEGL~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libEGL-devel", rpm:"mesa-libEGL-devel~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGLES", rpm:"mesa-libGLES~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libgbm", rpm:"mesa-libgbm~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libglapi", rpm:"mesa-libglapi~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libxatracker", rpm:"mesa-libxatracker~11.2.2~2.20160614.h1", rls:"EULEROS-2.0SP3"))) {
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
