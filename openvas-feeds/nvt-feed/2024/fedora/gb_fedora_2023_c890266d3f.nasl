# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.998902661003102");
  script_cve_id("CVE-2023-4863", "CVE-2023-4900", "CVE-2023-4901", "CVE-2023-4902", "CVE-2023-4903", "CVE-2023-4904", "CVE-2023-4905", "CVE-2023-4906", "CVE-2023-4907", "CVE-2023-4908", "CVE-2023-4909", "CVE-2023-5129", "CVE-2023-5186", "CVE-2023-5187", "CVE-2023-5217");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 18:37:00 +0000 (Fri, 29 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-c890266d3f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c890266d3f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c890266d3f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238432");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238433");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238832");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238833");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239523");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241119");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241120");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241194");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241195");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2023-c890266d3f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 117.0.5938.132. Fixes following security issues:

CVE-2023-5129 CVE-2023-5186

----

Update to 117.0.5938.92.

----

update to 117.0.5938.88

----

update to 117.0.5938.62. Fixes following security issues:

CVE-2023-4900 CVE-2023-4901 CVE-2023-4902 CVE-2023-4903 CVE-2023-4904
CVE-2023-4905 CVE-2023-4906 CVE-2023-4907 CVE-2023-4908 CVE-2023-4909

----

update to 116.0.5845.187. Fixes following security issue: CVE-2023-4863");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~117.0.5938.132~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~117.0.5938.132~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~117.0.5938.132~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~117.0.5938.132~2.fc39", rls:"FC39"))) {
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
