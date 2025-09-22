# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1575.1");
  script_cve_id("CVE-2020-10531", "CVE-2020-11080", "CVE-2020-7598", "CVE-2020-8174");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 15:29:25 +0000 (Tue, 25 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1575-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201575-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2020:1575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

nodejs10 was updated to version 10.21.0

CVE-2020-8174: Fixed multiple memory corruption in
 napi_get_value_string_*() (bsc#1172443).

CVE-2020-11080: Fixed a potential denial of service when receiving
 unreasonably large HTTP/2 SETTINGS frames (bsc#1172442).

CVE-2020-10531: Fixed an integer overflow in UnicodeString:doAppend()
 (bsc#1166844).

npm was updated to 6.14.3

CVE-2020-7598: Fixed an issue which could have tricked minimist into
 adding or modifying properties of Object.prototype (bsc#1166916).");

  script_tag(name:"affected", value:"'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.21.0~1.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.21.0~1.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.21.0~1.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.21.0~1.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.21.0~1.24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.21.0~1.24.1", rls:"SLES12.0"))) {
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
