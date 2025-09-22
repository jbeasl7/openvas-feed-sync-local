# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885259");
  script_cve_id("CVE-2023-5480", "CVE-2023-5482", "CVE-2023-5849", "CVE-2023-5850", "CVE-2023-5851", "CVE-2023-5852", "CVE-2023-5853", "CVE-2023-5854", "CVE-2023-5855", "CVE-2023-5856", "CVE-2023-5857", "CVE-2023-5858", "CVE-2023-5859", "CVE-2023-5996");
  script_tag(name:"creation_date", value:"2023-11-14 02:14:05 +0000 (Tue, 14 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 15:48:42 +0000 (Wed, 15 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-f83b5e84d3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-f83b5e84d3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-f83b5e84d3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247403");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247404");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247405");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247406");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247409");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247410");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247411");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247412");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247413");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247414");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247415");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247416");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247417");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247418");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247419");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247420");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247421");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247422");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247423");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247424");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247425");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247426");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247429");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247430");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2023-f83b5e84d3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 119.0.6045.123. Security fix for CVE-2023-5996

----

update to 119.0.6045.105. Security fixes:

 High CVE-2023-5480: Inappropriate implementation in Payments.
 High CVE-2023-5482: Insufficient data validation in USB.
 High CVE-2023-5849: Integer overflow in USB.
 Medium CVE-2023-5850: Incorrect security UI in Downloads.
 Medium CVE-2023-5851: Inappropriate implementation in Downloads.
 Medium CVE-2023-5852: Use after free in Printing.
 Medium CVE-2023-5853: Incorrect security UI in Downloads.
 Medium CVE-2023-5854: Use after free in Profiles.
 Medium CVE-2023-5855: Use after free in Reading Mode.
 Medium CVE-2023-5856: Use after free in Side Panel.
 Medium CVE-2023-5857: Inappropriate implementation in Downloads.
 Low CVE-2023-5858: Inappropriate implementation in WebApp Provider.
 Low CVE-2023-5859: Incorrect security UI in Picture In Picture.");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~119.0.6045.123~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~119.0.6045.123~1.fc39", rls:"FC39"))) {
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
