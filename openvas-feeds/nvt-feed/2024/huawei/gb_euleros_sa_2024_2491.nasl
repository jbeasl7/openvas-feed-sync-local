# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2491");
  script_cve_id("CVE-2024-23638");
  script_tag(name:"creation_date", value:"2024-09-23 08:46:49 +0000 (Mon, 23 Sep 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 23:05:12 +0000 (Tue, 30 Jan 2024)");

  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2024-2491)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2491");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2491");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'squid' package(s) announced via the EulerOS-SA-2024-2491 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid is a caching proxy for the Web. Due to an expired pointer reference bug, Squid prior to version 6.6 is vulnerable to a Denial of Service attack against Cache Manager error responses. This problem allows a trusted client to perform Denial of Service when generating error pages for Client Manager reports. Squid older than 5.0.5 have not been tested and should be assumed to be vulnerable. All Squid-5.x up to and including 5.9 are vulnerable. All Squid-6.x up to and including 6.5 are vulnerable. This bug is fixed by Squid version 6.6. In addition, patches addressing this problem for the stable releases can be found in Squid's patch archives. As a workaround, prevent access to Cache Manager using Squid's main access control: `http_access deny manager`.(CVE-2024-23638)");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.2~2.h22.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
