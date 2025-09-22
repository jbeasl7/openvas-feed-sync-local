# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885222");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:13 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-7934802344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7934802344");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7934802344");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221799");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239431");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239594");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239613");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239623");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239624");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243253");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cachelib, fb303, fbthrift, fizz, folly, mcrouter, mvfst, proxygen, wangle, watchman, wdt' package(s) announced via the FEDORA-2023-7934802344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update Folly stack to the latest 2023.10.16.00 tag

proxygen: Security fix for CVE-2023-44487");

  script_tag(name:"affected", value:"'cachelib, fb303, fbthrift, fizz, folly, mcrouter, mvfst, proxygen, wangle, watchman, wdt' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"cachelib", rpm:"cachelib~17^20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cachelib-debuginfo", rpm:"cachelib-debuginfo~17^20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cachelib-debugsource", rpm:"cachelib-debugsource~17^20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cachelib-devel", rpm:"cachelib-devel~17^20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fb303", rpm:"fb303~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fb303-debuginfo", rpm:"fb303-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fb303-debugsource", rpm:"fb303-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fb303-devel", rpm:"fb303-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbthrift", rpm:"fbthrift~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbthrift-debuginfo", rpm:"fbthrift-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbthrift-debugsource", rpm:"fbthrift-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbthrift-devel", rpm:"fbthrift-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbthrift-devel-debuginfo", rpm:"fbthrift-devel-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fizz", rpm:"fizz~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fizz-debuginfo", rpm:"fizz-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fizz-debugsource", rpm:"fizz-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fizz-devel", rpm:"fizz-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fizz-devel-debuginfo", rpm:"fizz-devel-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"folly", rpm:"folly~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"folly-debuginfo", rpm:"folly-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"folly-debugsource", rpm:"folly-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"folly-devel", rpm:"folly-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"folly-docs", rpm:"folly-docs~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mcrouter", rpm:"mcrouter~0.41.0.20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mcrouter-debuginfo", rpm:"mcrouter-debuginfo~0.41.0.20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mcrouter-debugsource", rpm:"mcrouter-debugsource~0.41.0.20231016~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvfst", rpm:"mvfst~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvfst-debuginfo", rpm:"mvfst-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvfst-debugsource", rpm:"mvfst-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mvfst-devel", rpm:"mvfst-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen", rpm:"proxygen~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen-debuginfo", rpm:"proxygen-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen-debugsource", rpm:"proxygen-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen-devel", rpm:"proxygen-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen-libs", rpm:"proxygen-libs~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proxygen-libs-debuginfo", rpm:"proxygen-libs-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pywatchman", rpm:"python3-pywatchman~2021.05.10.00~24.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pywatchman-debuginfo", rpm:"python3-pywatchman-debuginfo~2021.05.10.00~24.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wangle", rpm:"wangle~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wangle-debuginfo", rpm:"wangle-debuginfo~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wangle-debugsource", rpm:"wangle-debugsource~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wangle-devel", rpm:"wangle-devel~2023.10.16.00~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"watchman", rpm:"watchman~2021.05.10.00~24.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"watchman-debuginfo", rpm:"watchman-debuginfo~2021.05.10.00~24.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"watchman-debugsource", rpm:"watchman-debugsource~2021.05.10.00~24.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt", rpm:"wdt~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt-debuginfo", rpm:"wdt-debuginfo~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt-debugsource", rpm:"wdt-debugsource~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt-devel", rpm:"wdt-devel~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt-libs", rpm:"wdt-libs~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wdt-libs-debuginfo", rpm:"wdt-libs-debuginfo~1.32.1910230^20230711git3b52ef5~2.fc39", rls:"FC39"))) {
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
