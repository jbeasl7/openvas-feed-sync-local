# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1549");
  script_cve_id("CVE-2013-1944", "CVE-2014-0015", "CVE-2014-0138", "CVE-2014-3613", "CVE-2014-8150", "CVE-2016-5419", "CVE-2016-7141", "CVE-2016-8615", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624", "CVE-2016-9586", "CVE-2017-1000257", "CVE-2017-8817", "CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122");
  script_tag(name:"creation_date", value:"2020-01-23 12:12:05 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-09 12:36:10 +0000 (Mon, 09 Apr 2018)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2019-1549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1549");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1549");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2019-1549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw was found in the way libcurl checks values returned by the openldap ldap_get_attribute_ber() function. A malicious LDAP server could use this flaw to crash a libcurl client application via a specially crafted LDAP reply.(CVE-2018-1000121)

It was found that libcurl did not safely parse FTP URLs when using the CURLOPT_FTP_FILEMETHOD method. An attacker, able to provide a specially crafted FTP URL to an application using libcurl, could write a NULL byte at an arbitrary location, resulting in a crash, or an unspecified behavior.(CVE-2018-1000120)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2016-8623)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2016-8622)

It was found that the libcurl library did not prevent TLS session resumption when the client certificate had changed. An attacker could potentially use this flaw to hijack the authentication of the connection by leveraging a previously created connection with a different client certificate.(CVE-2016-5419)

A buffer overrun flaw was found in the IMAP handler of libcurl. By tricking an unsuspecting user into connecting to a malicious IMAP server, an attacker could exploit this flaw to potentially cause information disclosure or crash the application.(CVE-2017-1000257)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2016-8624)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2016-8621)

A buffer over-read exists in curl 7.20.0 to and including curl 7.58.0 in the RTSP+RTP handling code that allows an attacker to cause a denial of service or information leakage(CVE-2018-1000122)
** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2016-9586)

The FTP wildcard function in curl and libcurl before 7.57.0 allows remote attackers to cause a denial of service (out-of-bounds read and application crash) or possibly have unspecified other impact via a string that ends with an '' character.(CVE-2017-8817)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~46.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~46.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
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
