# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1057");
  script_cve_id("CVE-2016-7050");
  script_tag(name:"creation_date", value:"2020-01-23 10:41:28 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-16 12:03:40 +0000 (Fri, 16 Jun 2017)");

  script_name("Huawei EulerOS: Security Advisory for resteasy-base (EulerOS-SA-2016-1057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1057");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2016-1057");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'resteasy-base' package(s) announced via the EulerOS-SA-2016-1057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that under certain conditions RESTEasy could be forced to parse a request with SerializableProvider, resulting in deserialization of potentially untrusted data. An attacker could possibly use this flaw execute arbitrary code with the permissions of the application using RESTEasy.(CVE-2016-7050)");

  script_tag(name:"affected", value:"'resteasy-base' package(s) on Huawei EulerOS V2.0SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-atom-provider", rpm:"resteasy-base-atom-provider~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-client", rpm:"resteasy-base-client~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-jackson-provider", rpm:"resteasy-base-jackson-provider~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-jaxb-provider", rpm:"resteasy-base-jaxb-provider~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-jaxrs", rpm:"resteasy-base-jaxrs~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-jaxrs-api", rpm:"resteasy-base-jaxrs-api~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resteasy-base-jettison-provider", rpm:"resteasy-base-jettison-provider~3.0.6~4", rls:"EULEROS-2.0SP1"))) {
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
