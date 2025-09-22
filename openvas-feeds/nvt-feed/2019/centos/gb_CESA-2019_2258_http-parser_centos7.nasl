# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883105");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2018-7159", "CVE-2018-12121");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 17:54:00 +0000 (Tue, 06 Sep 2022)");
  script_tag(name:"creation_date", value:"2019-09-19 02:02:34 +0000 (Thu, 19 Sep 2019)");
  script_name("CentOS Update for http-parser CESA-2019:2258 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:2258");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-September/023439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'http-parser'
  package(s) announced via the CESA-2019:2258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The http-parser package provides a utility for parsing HTTP messages. It
parses both requests and responses. The parser is designed to be used in
performance HTTP applications. It does not make any system calls or
allocations, it does not buffer data, and it can be interrupted at any
time. Depending on your architecture, it only requires about 40 bytes of
data per message stream.

Security Fix(es):

  * nodejs: Denial of Service with large HTTP headers (CVE-2018-12121)

  * nodejs: HTTP parser allowed for spaces inside Content-Length header
values (CVE-2018-7159)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section.");

  script_tag(name:"affected", value:"'http-parser' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"http-parser", rpm:"http-parser~2.7.1~8.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"http-parser-devel", rpm:"http-parser-devel~2.7.1~8.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
