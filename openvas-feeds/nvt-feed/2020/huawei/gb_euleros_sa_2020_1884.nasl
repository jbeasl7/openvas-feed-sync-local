# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1884");
  script_cve_id("CVE-2019-12520", "CVE-2019-12524", "CVE-2019-12528");
  script_tag(name:"creation_date", value:"2020-08-31 07:04:21 +0000 (Mon, 31 Aug 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 15:11:10 +0000 (Wed, 29 Apr 2020)");

  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2020-1884)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1884");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1884");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'squid' package(s) announced via the EulerOS-SA-2020-1884 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Squid through 4.7 and 5. When receiving a request, Squid checks its cache to see if it can serve up a response. It does this by making a MD5 hash of the absolute URL of the request. If found, it servers the request. The absolute URL can include the decoded UserInfo (username and password) for certain protocols. This decoded info is prepended to the domain. This allows an attacker to provide a username that has special characters to delimit the domain, and treat the rest of the URL as a path or query string. An attacker could first make a request to their domain using an encoded username, then when a request for the target domain comes in that decodes to the exact URL, it will serve the attacker's HTML instead of the real HTML. On Squid servers that also act as reverse proxies, this allows an attacker to gain access to features that only reverse proxies can use, such as ESI.(CVE-2019-12520)

An issue was discovered in Squid through 4.7. When handling requests from users, Squid checks its rules to see if the request should be denied. Squid by default comes with rules to block access to the Cache Manager, which serves detailed server information meant for the maintainer. This rule is implemented via url_regex. The handler for url_regex rules URL decodes an incoming request. This allows an attacker to encode their URL to bypass the url_regex check, and gain access to the blocked resource.(CVE-2019-12524)

An issue was discovered in Squid before 4.10. It allows a crafted FTP server to trigger disclosure of sensitive information from heap memory, such as information associated with other users' sessions or non-Squid processes.(CVE-2019-12528)");

  script_tag(name:"affected", value:"'squid' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.2~2.h5.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
