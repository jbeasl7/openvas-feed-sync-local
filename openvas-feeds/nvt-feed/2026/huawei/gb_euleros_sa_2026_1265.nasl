# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1265");
  script_cve_id("CVE-2025-68276", "CVE-2025-68468", "CVE-2025-68471");
  script_tag(name:"creation_date", value:"2026-03-10 04:52:39 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for avahi (EulerOS-SA-2026-1265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1265");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'avahi' package(s) announced via the EulerOS-SA-2026-1265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Avahi is a system which facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite. In 0.9-rc2 and earlier, an unprivileged local users can crash avahi-daemon (with wide-area disabled) by creating record browsers with the AVAHI_LOOKUP_USE_WIDE_AREA flag set via D-Bus. This can be done by either calling the RecordBrowserNew method directly or creating hostname/address/service resolvers/browsers that create those browsers internally themselves.(CVE-2025-68276)

Avahi is a system which facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite. In 0.9-rc2 and earlier, avahi-daemon can be crashed by sending 2 unsolicited announcements with CNAME resource records 2 seconds apart.(CVE-2025-68471)

Avahi is a system which facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite. In 0.9-rc2 and earlier, avahi-daemon can be crashed by sending unsolicited announcements containing CNAME resource records pointing it to resource records with short TTLs. As soon as they expire avahi-daemon crashes.(CVE-2025-68468)");

  script_tag(name:"affected", value:"'avahi' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"avahi-libs", rpm:"avahi-libs~0.8~18.h4.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
