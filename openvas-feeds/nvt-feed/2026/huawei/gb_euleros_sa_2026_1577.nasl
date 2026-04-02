# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1577");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087");
  script_tag(name:"creation_date", value:"2026-03-17 04:55:49 +0000 (Tue, 17 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-06 17:19:39 +0000 (Fri, 06 Feb 2026)");

  script_name("Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2026-1577)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1577");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1577");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2026-1577 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow problem was found in glib through an incorrect calculation of buffer size in the g_escape_uri_string() function. If the string to escape contains a very large number of unacceptable characters (which would need escaping), the calculation of the length of the escaped string could overflow, leading to a potential write off the end of the newly allocated string.(CVE-2025-13601)

A flaw was found in GLib (Gnome Lib). This vulnerability allows a remote attacker to cause heap corruption, leading to a denial of service or potential code execution via a buffer-underflow in the GVariant parser when processing maliciously crafted input strings.(CVE-2025-14087)");

  script_tag(name:"affected", value:"'glib2' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.68.1~10.h26.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
