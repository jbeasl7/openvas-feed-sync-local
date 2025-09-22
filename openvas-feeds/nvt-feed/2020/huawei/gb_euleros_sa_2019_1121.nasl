# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1121");
  script_cve_id("CVE-2018-1000888");
  script_tag(name:"creation_date", value:"2020-01-23 11:32:04 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-11 18:48:34 +0000 (Mon, 11 Feb 2019)");

  script_name("Huawei EulerOS: Security Advisory for php-pear (EulerOS-SA-2019-1121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1121");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1121");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'php-pear' package(s) announced via the EulerOS-SA-2019-1121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PEAR Archive_Tar version 1.4.3 and earlier contains a CWE-502, CWE-915 vulnerability in the Archive_Tar class. There are several file operations with `$v_header['filename']` as parameter (such as file_exists, is_file, is_dir, etc). When extract is called without a specific prefix path, we can trigger unserialization by crafting a tar file with `phar://[path_to_malicious_phar_file]` as path. Object injection can be used to trigger destruct in the loaded PHP classes, e.g. the Archive_Tar class itself. With Archive_Tar object injection, arbitrary file deletion can occur because `@unlink($this->_temp_tarname)` is called. If another class with useful gadget is loaded, it may possible to cause remote code execution that can result in files being deleted or possibly modified. (CVE-2018-1000888)");

  script_tag(name:"affected", value:"'php-pear' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~21.h1", rls:"EULEROS-2.0SP2"))) {
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
