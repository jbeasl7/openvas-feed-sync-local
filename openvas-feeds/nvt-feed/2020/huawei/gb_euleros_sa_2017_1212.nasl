# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1212");
  script_cve_id("CVE-2016-10164", "CVE-2017-2625", "CVE-2017-2626");
  script_tag(name:"creation_date", value:"2020-01-23 10:59:28 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 16:19:18 +0000 (Wed, 22 Feb 2017)");

  script_name("Huawei EulerOS: Security Advisory for libXpm, libXdmcp, libICE (EulerOS-SA-2017-1212)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1212");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1212");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libICE, libXdmcp, libXpm' package(s) announced via the EulerOS-SA-2017-1212 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw leading to a heap-based buffer overflow was found in libXpm. An attacker could use this flaw to crash an application using libXpm via a specially crafted XPM file. (CVE-2016-10164)

It was discovered that libXdmcp used weak entropy to generate session keys. On a multi-user system using xdmcp, a local attacker could potentially use information available from the process list to brute force the key, allowing them to hijack other users' sessions. (CVE-2017-2625)

It was discovered that libICE used a weak entropy to generate keys. A local attacker could potentially use this flaw for session hijacking using the information available from the process list. (CVE-2017-2626)");

  script_tag(name:"affected", value:"'libICE, libXdmcp, libXpm' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libICE", rpm:"libICE~1.0.9~9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libICE-devel", rpm:"libICE-devel~1.0.9~9", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXdmcp", rpm:"libXdmcp~1.1.2~6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm", rpm:"libXpm~3.5.12~1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXpm-devel", rpm:"libXpm-devel~3.5.12~1", rls:"EULEROS-2.0SP2"))) {
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
