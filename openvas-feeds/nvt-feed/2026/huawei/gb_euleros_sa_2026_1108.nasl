# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1108");
  script_cve_id("CVE-2025-58060", "CVE-2025-58364");
  script_tag(name:"creation_date", value:"2026-02-02 04:58:24 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for cups (EulerOS-SA-2026-1108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1108");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1108");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'cups' package(s) announced via the EulerOS-SA-2026-1108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.12 and earlier, when the `AuthType` is set to anything but `Basic`, if the request contains an `Authorization: Basic ...` header, the password is not checked. This results in authentication bypass. Any configuration that allows an `AuthType` that is not `Basic` is affected. Version 2.4.13 fixes the issue.(CVE-2025-58060)

OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.12 and earlier, an unsafe deserialization and validation of printer attributes causes null dereference in the libcups library. This is a remote DoS vulnerability available in local subnet in default configurations. It can cause the cups & cups-browsed to crash, on all the machines in local network who are listening for printers (so by default for all regular linux machines). On systems where the vulnerability CVE-2024-47176 (cups-filters 1.x/cups-browsed 2.x vulnerability) was not fixed, and the firewall on the machine does not reject incoming communication to IPP port, and the machine is set to be available to public internet, attack vector 'Network' is possible. The current versions of CUPS and cups-browsed projects have the attack vector 'Adjacent' in their default configurations. Version 2.4.13 contains a patch for CVE-2025-58364.(CVE-2025-58364)");

  script_tag(name:"affected", value:"'cups' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~2.2.13~4.h11.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
