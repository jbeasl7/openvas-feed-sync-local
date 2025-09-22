# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885148");
  script_cve_id("CVE-2023-38552", "CVE-2023-39333", "CVE-2023-44487", "CVE-2023-45143");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:15 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-dbe64661af)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-dbe64661af");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-dbe64661af");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/october-2023-security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18' package(s) announced via the FEDORA-2023-dbe64661af advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## 2023-10-13, Version 18.18.2 'Hydrogen' (LTS), @RafaelGSS

This is a security release.

### Notable Changes

The following CVEs are fixed in this release:

* [CVE-2023-44487]([link moved to references]): `nghttp2` Security Release (High)
* [CVE-2023-45143]([link moved to references]): `undici` Security Release (High)
* [CVE-2023-38552]([link moved to references]): Integrity checks according to policies can be circumvented (Medium)
* [CVE-2023-39333]([link moved to references]): Code injection via WebAssembly export names (Low)

More detailed information on each of the vulnerabilities can be found in [October 2023 Security Releases]([link moved to references]) blog post.");

  script_tag(name:"affected", value:"'nodejs18' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-full-i18n", rpm:"nodejs18-full-i18n~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-libs", rpm:"nodejs18-libs~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-libs-debuginfo", rpm:"nodejs18-libs-debuginfo~18.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-npm", rpm:"nodejs18-npm~9.8.1~1.18.18.2.1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-10.2-devel", rpm:"v8-10.2-devel~10.2.154.26~1.18.18.2.1.fc39", rls:"FC39"))) {
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
