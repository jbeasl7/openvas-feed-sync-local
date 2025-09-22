# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1108");
  script_cve_id("CVE-2018-1000075", "CVE-2018-1000076");
  script_tag(name:"creation_date", value:"2020-01-23 11:12:48 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:30:37 +0000 (Thu, 05 Apr 2018)");

  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2018-1108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1108");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2018-1108");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2018-1108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier, prior to trunk revision 62422 contains an infinite loop caused by negative size vulnerability in ruby gem package tar header that can result in a negative size could cause an infinite loop.. (CVE-2018-1000075)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier, prior to trunk revision 62422 contains a Improper Verification of Cryptographic Signature vulnerability in package.rb that can result in a mis-signed gem could be installed, as the tarball would contain multiple gem signatures.. (CVE-2018-1000076)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.648~33.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.648~33.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.0.0.648~33.h6", rls:"EULEROS-2.0SP2"))) {
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
