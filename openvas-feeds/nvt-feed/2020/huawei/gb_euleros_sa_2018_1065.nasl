# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1065");
  script_cve_id("CVE-2017-5495", "CVE-2018-5379");
  script_tag(name:"creation_date", value:"2020-01-23 11:11:16 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 18:39:35 +0000 (Wed, 14 Mar 2018)");

  script_name("Huawei EulerOS: Security Advisory for quagga (EulerOS-SA-2018-1065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1065");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2018-1065");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'quagga' package(s) announced via the EulerOS-SA-2018-1065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A double-free vulnerability was found in Quagga. A BGP peer could send a specially crafted UPDATE message which would cause allocated blocks of memory to be free()d more than once, potentially leading to a crash or other issues.(CVE-2018-5379)

All versions of Quagga, 0.93 through 1.1.0, are vulnerable to an unbounded memory allocation in the telnet 'vty' CLI, leading to a Denial-of-Service of Quagga daemons, or even the entire host. When Quagga daemons are configured with their telnet CLI enabled, anyone who can connect to the TCP ports can trigger this vulnerability, prior to authentication. Most distributions restrict the Quagga telnet interface to local access only by default. The Quagga telnet interface 'vty' input buffer grows automatically, without bound, so long as a newline is not entered. This allows an attacker to cause the Quagga daemon to allocate unbounded memory by sending very long strings without a newline. Eventually the daemon is terminated by the system, or the system itself runs out of memory.(CVE-2017-5495)");

  script_tag(name:"affected", value:"'quagga' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.4~5.h2", rls:"EULEROS-2.0SP2"))) {
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
