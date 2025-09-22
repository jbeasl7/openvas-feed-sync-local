# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1757");
  script_cve_id("CVE-2021-23239", "CVE-2021-23240");
  script_tag(name:"creation_date", value:"2021-04-13 06:16:31 +0000 (Tue, 13 Apr 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 21:32:10 +0000 (Thu, 14 Jan 2021)");

  script_name("Huawei EulerOS: Security Advisory for sudo (EulerOS-SA-2021-1757)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1757");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1757");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'sudo' package(s) announced via the EulerOS-SA-2021-1757 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition vulnerability was found in the temporary file handling of sudoedit's SELinux RBAC support. On systems where SELinux is enabled, this flaw allows a malicious user with sudoedit permissions to set the owner of an arbitrary file to the user ID of the target user, potentially leading to local privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2021-23240)

A flaw was found in sudoedit. A race condition vulnerability and improper symbolic link resolution could be used by a local unprivileged user to test for the existence of directories and files not normally accessible to the user. This flaw cannot be used to read the content or write to arbitrary files on the file system. The highest threat from this vulnerability is to data confidentiality.(CVE-2021-23239)");

  script_tag(name:"affected", value:"'sudo' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.27~5.h9.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
