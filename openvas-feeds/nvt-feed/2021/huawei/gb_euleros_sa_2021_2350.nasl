# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2350");
  script_cve_id("CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653");
  script_tag(name:"creation_date", value:"2021-09-04 02:25:52 +0000 (Sat, 04 Sep 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 19:58:00 +0000 (Thu, 03 Dec 2020)");

  script_name("Huawei EulerOS: Security Advisory for spice-vdagent (EulerOS-SA-2021-2350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2350");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-2350");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'spice-vdagent' package(s) announced via the EulerOS-SA-2021-2350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the spice-vdagentd daemon handled file transfers from the host system to the virtual machine. Any unprivileged local guest user with access to the UNIX domain socket path `/run/spice-vdagentd/spice-vdagent-sock` could use this flaw to perform a memory denial of service for spice-vdagentd or even other processes in the VM system. The highest threat from this vulnerability is to system availability. This flaw affects spice-vdagent versions 0.20 and previous versions.(CVE-2020-25650)

A flaw was found in the SPICE file transfer protocol. File data from the host system can end up in full or in parts in the client connection of an illegitimate local user in the VM system. Active file transfers from other users could also be interrupted, resulting in a denial of service. The highest threat from this vulnerability is to data confidentiality as well as system availability. This flaw affects spice-vdagent versions 0.20 and prior.(CVE-2020-25651)

A flaw was found in the spice-vdagentd daemon, where it did not properly handle client connections that can be established via the UNIX domain socket in `/run/spice-vdagentd/spice-vdagent-sock`. Any unprivileged local guest user could use this flaw to prevent legitimate agents from connecting to the spice-vdagentd daemon, resulting in a denial of service. The highest threat from this vulnerability is to system availability. This flaw affects spice-vdagent versions 0.20 and prior.(CVE-2020-25652)

A race condition vulnerability was found in the way the spice-vdagentd daemon handled new client connections. This flaw may allow an unprivileged local guest user to become the active agent for spice-vdagentd, possibly resulting in a denial of service or information leakage from the host. The highest threat from this vulnerability is to data confidentiality as well as system availability. This flaw affects spice-vdagent versions 0.20 and prior.(CVE-2020-25653)");

  script_tag(name:"affected", value:"'spice-vdagent' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"spice-vdagent", rpm:"spice-vdagent~0.14.0~15.h3.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
