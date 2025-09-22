# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1571");
  script_cve_id("CVE-2018-12405", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498", "CVE-2018-18506", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9810", "CVE-2019-9813");
  script_tag(name:"creation_date", value:"2020-01-23 12:15:18 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 19:35:56 +0000 (Mon, 29 Apr 2019)");

  script_name("Huawei EulerOS: Security Advisory for firefox (EulerOS-SA-2019-1571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1571");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'firefox' package(s) announced via the EulerOS-SA-2019-1571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla: Memory safety bugs fixed in Firefox 66 and Firefox ESR 60.6 (CVE-2019-9788)

Mozilla: Use-after-free when removing in-use DOM elements (CVE-2019-9790)

Mozilla: Type inference is incorrect for constructors entered through on-stack replacement with IonMonkey (CVE-2019-9791)

Mozilla: IonMonkey leaks JS_OPTIMIZED_OUT magic value to script (CVE-2019-9792)

Mozilla: Improper bounds checks when Spectre mitigations are disabled (CVE-2019-9793)

Mozilla: Type-confusion in IonMonkey JIT compiler (CVE-2019-9795)

Mozilla: Use-after-free with SMIL animation controller (CVE-2019-9796)

Mozilla: Proxy Auto-Configuration file can define localhost access to be proxied (CVE-2018-18506)

Mozilla: Memory safety bugs fixed in Firefox 64 and Firefox ESR 60.4 (CVE-2018-12405)

Mozilla: Memory corruption in Angle (CVE-2018-17466)

Mozilla: Use-after-free with select element (CVE-2018-18492)

Mozilla: Buffer overflow in accelerated 2D canvas with Skia (CVE-2018-18493)

Mozilla: Same-origin policy violation using location attribute and performance.getEntries to steal cross-origin URLs (CVE-2018-18494)

Mozilla: Integer overflow when calculating buffer sizes for images (CVE-2018-18498)

Mozilla: IonMonkey MArraySlice has incorrect alias information (CVE-2019-9810)

Mozilla: Ionmonkey type confusion with __proto__ mutations (CVE-2019-9813)");

  script_tag(name:"affected", value:"'firefox' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.6.1~1.h1", rls:"EULEROS-2.0SP3"))) {
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
