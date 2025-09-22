# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1439");
  script_cve_id("CVE-2014-6272", "CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197");
  script_tag(name:"creation_date", value:"2020-01-23 11:47:01 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-21 14:29:54 +0000 (Tue, 21 Mar 2017)");

  script_name("Huawei EulerOS: Security Advisory for libevent (EulerOS-SA-2019-1439)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1439");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1439");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libevent' package(s) announced via the EulerOS-SA-2019-1439 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer overflows in the evbuffer API in Libevent 1.4.x before 1.4.15, 2.0.x before 2.0.22, and 2.1.x before 2.1.5-beta allow context-dependent attackers to cause a denial of service or possibly have other unspecified impact via 'insanely large inputs' to the (1) evbuffer_add, (2) evbuffer_expand, or (3) bufferevent_write function, which triggers a heap-based buffer overflow or an infinite loop. NOTE: this identifier has been SPLIT per ADT3 due to different affected versions. See CVE-2015-6525 for the functions that are only affected in 2.0 and later.(CVE-2014-6272)

An out of bounds read vulnerability was found in libevent in the search_make_new function. If an attacker could cause an application using libevent to attempt resolving an empty hostname, an out of bounds read could occur possibly leading to a crash.(CVE-2016-10197)

A vulnerability was found in libevent with the parsing of DNS requests and replies. An attacker could send a forged DNS response to an application using libevent which could lead to reading data out of bounds on the heap, potentially disclosing a small amount of application memory.(CVE-2016-10195)

A vulnerability was found in libevent with the parsing of IPv6 addresses. If an attacker could cause an application using libevent to parse a malformed address in IPv6 notation of more than 2GiB in length, a stack overflow would occur leading to a crash.(CVE-2016-10196)");

  script_tag(name:"affected", value:"'libevent' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"libevent", rpm:"libevent~2.0.21~4.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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
