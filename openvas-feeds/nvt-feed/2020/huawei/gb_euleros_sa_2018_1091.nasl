# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1091");
  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-7549");
  script_tag(name:"creation_date", value:"2020-01-23 11:12:20 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 18:55:57 +0000 (Fri, 16 Mar 2018)");

  script_name("Huawei EulerOS: Security Advisory for zsh (EulerOS-SA-2018-1091)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1091");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2018-1091");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'zsh' package(s) announced via the EulerOS-SA-2018-1091 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In builtin.c in zsh before 5.4, when sh compatibility mode is used, there is a NULL pointer dereference during processing of the cd command with no argument if HOME is not set.(CVE-2017-18205)

zsh before 5.0.7 allows evaluation of the initial values of integer variables imported from the environment (instead of treating them as literal numbers). That could allow local privilege escalation, under some specific and atypical conditions where zsh is being invoked in privilege-elevation contexts when the environment has not been properly sanitized, such as when zsh is invoked by sudo on systems where 'env_reset' has been disabled.(CVE-2014-10070)

In exec.c in zsh before 5.0.7, there is a buffer overflow for very long fds in the '>& fd' syntax.(CVE-2014-10071)

A buffer overflow flaw was found in the zsh shell symbolic link resolver. A local, unprivileged user can create a specially crafted directory path which leads to a buffer overflow in the context of the user trying to do a symbolic link resolution in the aforementioned path. If the user affected is privileged, this leads to privilege escalation.(CVE-2017-18206)

In params.c in zsh through 5.4.2, there is a crash during a copy of an empty hash table, as demonstrated by typeset -p.(CVE-2018-7549)");

  script_tag(name:"affected", value:"'zsh' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.0.2~7.h5", rls:"EULEROS-2.0SP2"))) {
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
