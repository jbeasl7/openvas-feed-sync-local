# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1165");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698", "CVE-2017-2640");
  script_tag(name:"creation_date", value:"2020-01-23 10:54:33 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-24 19:54:35 +0000 (Mon, 24 Sep 2018)");

  script_name("Huawei EulerOS: Security Advisory for pidgin (EulerOS-SA-2017-1165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1165");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'pidgin' package(s) announced via the EulerOS-SA-2017-1165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way Pidgin's Mxit plug-in handled emoticons. A malicious remote server or a man-in-the-middle attacker could potentially use this flaw to crash Pidgin by sending a specially crafted emoticon. (CVE-2014-3695)

A denial of service flaw was found in the way Pidgin parsed Groupwise server messages. A malicious remote server or a man-in-the-middle attacker could potentially use this flaw to cause Pidgin to consume an excessive amount of memory, possibly leading to a crash, by sending a specially crafted message. (CVE-2014-3696)

An information disclosure flaw was discovered in the way Pidgin parsed XMPP messages. A malicious remote server or a man-in-the-middle attacker could potentially use this flaw to disclose a portion of memory belonging to the Pidgin process by sending a specially crafted XMPP message. (CVE-2014-3698)

An out-of-bounds write flaw was found in the way Pidgin processed XML content. A malicious remote server could potentially use this flaw to crash Pidgin or execute arbitrary code in the context of the pidgin process. (CVE-2017-2640)

It was found that Pidgin's SSL/TLS plug-ins had a flaw in the certificate validation functionality. An attacker could use this flaw to create a fake certificate, that Pidgin would trust, which could be used to conduct man-in-the-middle attacks against Pidgin. (CVE-2014-3694)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.10.11~5", rls:"EULEROS-2.0SP1"))) {
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
