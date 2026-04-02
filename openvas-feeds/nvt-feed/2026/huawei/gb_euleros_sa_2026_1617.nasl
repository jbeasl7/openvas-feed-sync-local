# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1617");
  script_cve_id("CVE-2025-61911", "CVE-2025-61912");
  script_tag(name:"creation_date", value:"2026-03-17 04:55:49 +0000 (Tue, 17 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:56:39 +0000 (Thu, 04 Dec 2025)");

  script_name("Huawei EulerOS: Security Advisory for python-ldap (EulerOS-SA-2026-1617)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1617");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1617");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-ldap' package(s) announced via the EulerOS-SA-2026-1617 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"python-ldap is a lightweight directory access protocol (LDAP) client API for Python. In versions prior to 3.4.5, ldap.dn.escape_dn_chars() escapes \x00 incorrectly by emitting a backslash followed by a literal NUL byte instead of the RFC-4514 hex form \00. Any application that uses this helper to construct DNs from untrusted input can be made to consistently fail before a request is sent to the LDAP server (e.g., AD), resulting in a client-side denial of service. Version 3.4.5 contains a patch for the issue.(CVE-2025-61912)

python-ldap is a lightweight directory access protocol (LDAP) client API for Python. In versions prior to 3.4.5, the sanitization method `ldap.filter.escape_filter_chars` can be tricked to skip escaping of special characters when a crafted `list` or `dict` is supplied as the `assertion_value` parameter, and the non-default `escape_mode=1` is configured. The method `ldap.filter.escape_filter_chars` supports 3 different escaping modes. `escape_mode=0` (default) and `escape_mode=2` happen to raise exceptions when a `list` or `dict` object is supplied as the `assertion_value` parameter. However, `escape_mode=1` computes without performing adequate logic to ensure a fully escaped return value. If an application relies on the vulnerable method in the `python-ldap` library to escape untrusted user input, an attacker might be able to abuse the vulnerability to launch ldap injection attacks which could potentially disclose or manipulate ldap data meant to be inaccessible to them. Version 3.4.5 fixes the issue by adding a type check at the start of the `ldap.filter.escape_filter_chars` method to raise an exception when the supplied `assertion_value` parameter is not of type `str`.(CVE-2025-61911)");

  script_tag(name:"affected", value:"'python-ldap' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"python-ldap-help", rpm:"python-ldap-help~3.3.1~2.h8.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldap", rpm:"python3-ldap~3.3.1~2.h8.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
