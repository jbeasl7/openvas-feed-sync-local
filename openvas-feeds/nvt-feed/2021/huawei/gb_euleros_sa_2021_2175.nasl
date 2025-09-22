# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2175");
  script_cve_id("CVE-2019-25031", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042");
  script_tag(name:"creation_date", value:"2021-07-13 12:57:52 +0000 (Tue, 13 Jul 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-30 15:03:54 +0000 (Fri, 30 Apr 2021)");

  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2021-2175)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2175");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-2175");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2021-2175 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25042)

** DISPUTED ** Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25041)

** DISPUTED ** Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25040)

** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25039)

** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in dnscrypt/dnscrypt.c. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25038)

** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy via an invalid packet. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25037)

** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25036)

** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25035)

Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading to an out-of-bounds write. (CVE-2019-25034)

** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in the regional allocator via the ALIGN_UP macro. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound installation cannot be remotely or locally exploited.(CVE-2019-25033)

** DISPUTED ** Unbound before 1.9.5 allows configuration injection in create_unbound_ad_servers.sh upon a successful man-in-the-middle attack against a cleartext HTTP session. NOTE: The vendor ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.7.3~18.h6.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.7.3~18.h6.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
