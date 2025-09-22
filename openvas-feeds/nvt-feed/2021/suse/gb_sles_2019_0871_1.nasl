# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0871.1");
  script_cve_id("CVE-2018-18335", "CVE-2018-18356", "CVE-2018-18506", "CVE-2019-5785", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9801", "CVE-2019-9810", "CVE-2019-9813");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 19:35:56 +0000 (Mon, 29 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0871-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0871-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190871-1/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-12/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-08/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-05/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2019:0871-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to version ESR 60.6.1 fixes the following issues:

Security issuess addressed:
update to Firefox ESR 60.6.1 (bsc#1130262):
CVE-2019-9813: Fixed Ionmonkey type confusion with __proto__ mutations

CVE-2019-9810: Fixed IonMonkey MArraySlice incorrect alias information Update to Firefox ESR 60.6 (bsc#1129821):
CVE-2018-18506: Fixed an issue with Proxy Auto-Configuration file

CVE-2019-9801: Fixed an issue which could allow Windows programs to be
 exposed to web content

CVE-2019-9788: Fixed multiple memory safety bugs

CVE-2019-9790: Fixed a Use-after-free vulnerability when removing in-use
 DOM elements

CVE-2019-9791: Fixed an incorrect Type inference for constructors
 entered through on-stack replacement with IonMonkey

CVE-2019-9792: Fixed an issue where IonMonkey leaks JS_OPTIMIZED_OUT
 magic value to script

CVE-2019-9793: Fixed multiple improper bounds checks when Spectre
 mitigations are disabled

CVE-2019-9794: Fixed an issue where command line arguments not discarded
 during execution

CVE-2019-9795: Fixed a Type-confusion vulnerability in IonMonkey JIT
 compiler

CVE-2019-9796: Fixed a Use-after-free vulnerability in SMIL animation
 controller Update to Firefox ESR 60.5.1 (bsc#1125330):
CVE-2018-18356: Fixed a use-after-free vulnerability in the Skia library
 which can occur when creating a path, leading to a potentially
 exploitable crash.

CVE-2019-5785: Fixed an integer overflow vulnerability in the Skia
 library which can occur after specific transform operations, leading to
 a potentially exploitable crash.

CVE-2018-18335: Fixed a buffer overflow vulnerability in the Skia
 library which can occur with Canvas 2D acceleration on macOS. This issue
 was addressed by disabling Canvas 2D acceleration in Firefox ESR. Note:
 this does not affect other versions and platforms where Canvas 2D
 acceleration is already disabled by default.

Other issue addressed:
Fixed an issue with MozillaFirefox-translations-common which was causing
 error on update (bsc#1127987).

Release notes:
[link moved to references] Release notes: [link moved to references]
Release notes:
[link moved to references]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.6.1~3.29.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~60.6.1~3.29.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~60.6.1~3.29.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~60.6.1~3.29.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.6.1~3.29.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.6.1~3.29.3", rls:"SLES15.0"))) {
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
