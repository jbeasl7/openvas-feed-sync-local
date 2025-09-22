# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884302");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2023-6856", "CVE-2023-6864", "CVE-2023-50761", "CVE-2023-50762", "CVE-2023-6857", "CVE-2023-6858", "CVE-2023-6859", "CVE-2023-6860", "CVE-2023-6861", "CVE-2023-6862", "CVE-2023-6863");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:59:57 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-05 14:31:52 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2024:0027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0027");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-January/099173.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2024:0027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This Update upgrades Thunderbird to version 115.6.0.

Security Fix(es):

  * Mozilla: Heap-buffer-overflow affecting WebGL &lt, code&gt, DrawElementsInstanced&lt, /code&gt, method with Mesa VM driver (CVE-2023-6856)

  * Mozilla: Memory safety bugs fixed in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6 (CVE-2023-6864)

  * Mozilla: S/MIME signature accepted despite mismatching message date (CVE-2023-50761)

  * Mozilla: Truncated signed text was shown with a valid OpenPGP signature (CVE-2023-50762)

  * Mozilla: Symlinks may resolve to smaller than expected buffers (CVE-2023-6857)

  * Mozilla: Heap buffer overflow in &lt, code&gt, nsTextFragment&lt, /code&gt, (CVE-2023-6858)

  * Mozilla: Use-after-free in PR_GetIdentitiesLayer (CVE-2023-6859)

  * Mozilla: Potential sandbox escape due to &lt, code&gt, VideoBridge&lt, /code&gt, lack of texture validation (CVE-2023-6860)

  * Mozilla: Heap buffer overflow affected &lt, code&gt, nsWindow::PickerOpen(void)&lt, /code&gt, in headless mode (CVE-2023-6861)

  * Mozilla: Use-after-free in &lt, code&gt, nsDNSService&lt, /code&gt, (CVE-2023-6862)

  * Mozilla: Undefined behavior in &lt, code&gt, ShutdownObserver()&lt, /code&gt, (CVE-2023-6863)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~115.6.0~1.el7.centos", rls:"CentOS7"))) {
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