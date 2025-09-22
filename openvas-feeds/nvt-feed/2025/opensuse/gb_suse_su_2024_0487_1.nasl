# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0487.1");
  script_cve_id("CVE-2020-7753", "CVE-2021-3807", "CVE-2021-3918", "CVE-2021-43138", "CVE-2021-43798", "CVE-2021-43815", "CVE-2022-0155", "CVE-2022-41715");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 18:46:46 +0000 (Tue, 16 Nov 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0487-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0487-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240487-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218844");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017931.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2024:0487-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-lusitaniae-apache_exporter:

- Do not strip if SUSE Linux Enterprise 15 SP3
- Exclude debug for Red Hat Enterprise Linux >= 8
- Build with Go >= 1.20 when the OS is not Red Hat Enterprise Linux

mgr-daemon:

- Version 4.3.8-1
 * Update translation strings

prometheus-postgres_exporter:

- Remove duplicated call to systemd requirements
- Do not build debug if Red Hat Enterprise Linux >= 8
- Do not strip if SUSE Linux Enterprise 15 SP3
- Build at least with with Go >= 1.18 on Red Hat Enterprise Linux
- Build with Go >= 1.20 elsewhere

spacecmd:

- Version 4.3.26-1
 * Update translation strings

spacewalk-client-tools:

- Version 4.3.18-1
 * Update translation strings

uyuni-proxy-systemd-services:

- Version 4.3.10-1
 * Update the image version
- Version 4.3.9-1
 * Integrate the containerized proxy into the usual rel-eng workflow");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.0~150000.1.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.1~150000.1.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.26~150000.3.113.1", rls:"openSUSELeap15.5"))) {
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
