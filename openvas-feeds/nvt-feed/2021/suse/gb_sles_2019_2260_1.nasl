# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2260.1");
  script_cve_id("CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 18:27:15 +0000 (Wed, 21 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2260-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192260-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs8' package(s) announced via the SUSE-SU-2019:2260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs8 to version 8.16.1 fixes the following issues:

Security issues fixed:
CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
 window size manipulation and stream prioritization manipulation,
 potentially leading to a denial of service (bsc#1146091).

CVE-2019-9512: Fixed HTTP/2 flood using PING frames results in unbounded
 memory growth (bsc#1146099).

CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
 resource loops, potentially leading to a denial of service.
 (bsc#1146094).

CVE-2019-9514: Fixed HTTP/2 implementation that is vulnerable to a reset
 flood, potentially leading to a denial of service (bsc#1146095).

CVE-2019-9515: Fixed HTTP/2 flood using SETTINGS frames results in
 unbounded memory growth (bsc#1146100).

CVE-2019-9516: Fixed HTTP/2 implementation that is vulnerable to a
 header leak, potentially leading to a denial of service (bsc#1146090).

CVE-2019-9517: Fixed HTTP/2 implementations that are vulnerable to
 unconstrained interal data buffering (bsc#1146097).

CVE-2019-9518: Fixed HTTP/2 implementation that is vulnerable to a flood
 of empty frames, potentially leading to a denial of service
 (bsc#1146093).

Bug fixes:
Fixed that npm resolves its default config file like in all other
 versions, as /etc/nodejs/npmrc (bsc#1144919).");

  script_tag(name:"affected", value:"'nodejs8' package(s) on SUSE Linux Enterprise Module for Web Scripting 15, SUSE Linux Enterprise Module for Web Scripting 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.16.1~3.20.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.16.1~3.20.1", rls:"SLES15.0SP1"))) {
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
