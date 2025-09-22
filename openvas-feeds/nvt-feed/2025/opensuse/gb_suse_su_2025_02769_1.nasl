# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02769.1");
  script_cve_id("CVE-2025-30204");
  script_tag(name:"creation_date", value:"2025-08-14 04:12:02 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02769-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502769-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240511");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041173.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'amber-cli' package(s) announced via the SUSE-SU-2025:02769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for amber-cli fixes the following issues:

- Update to version 1.13.1+git20250329.c2e3bb8:
 * CVE-2025-30204: Fixed jwt-go excessive memory
 allocation during header parsing (bsc#1240511)
 * jwt version upgrade (#174)
 * Update policy size limit to 20k (#173)
 * Update tenant user model with latest changes (#172)
 * Fix/workflow (#171)
 * Upgrade GO version to 1.23.6 (#170)
 * Update golang jwt dependency (#169)
 * Update TMS roles struct (#167)
 * Update jwt dependency version (#165)
 * Add changes to support JWT (#163)
 * Update roles struct to be in sync with TMS (#164)
 * go upgrade to 1.22.7 (#162)
 * CASSINI-22266: Added permissions in ci workflow files (#153)
 * Add check for missing Security.md file (#150)
 * Go version upgrade to 1.22.5 (#148)
 * CLI changes (#140)
 * Bump github.com/hashicorp/go-retryablehttp from 0.7.4 to 0.7.7 (#147)
 * Update product model to include multiple plan IDs (#146)
 * Updated the help section (#145)
 * Mark policy type field as not required (#144)
 * Upgrade/goversion 1.22.3 (#143)
 * Remove policy type and attestation type check for policy creation (#142)
 * Go version upgrade 1.22.2 (#141)
 * Fix error message to include the correct set of characters (#138)
 * UT coverage 80.9% (#137)
 * Fix push installer workflow (#136)
 * 3rd party versions upgrade (#133)
 * GO version upgrade to 1.22.0 (#132)
 * Fix/go version 1.21.6 (#127)
 * Update API key validation regex as per latest changes (#125)
 * Update API key validation regex as per latest changes (#124)
 * dependency version upgrade (#123)
 * Update tag create model (#121)
 * CASSINI-10113: Add scans in CI (#99)
 * corrected minor check condition (#120)
 * Add check to validate env variable before setting (#119)
 * Add version-check script (#118)
 * Add file path check for invalid characters (#116)
 * Update compoenent version (#117)
 * Update README as per suggestions (#113) (#115)
 * Added HTTP scheme validation to avoid API Key leakage (#108)
 * CASSINI-10987 Golang version upgrade to 1.21.4 (#114)
 * Update policy model as per the latest changes (#109)
 * Remove branch info from on schedule (#106)
 * Add BDBA scan to CI (#104)
 * Update CLI URL (#105)
 * updated licenses (#102)
 * Updated version of all components to v1.0.0 for GA (#100)
 * Validate the email id input before requesting list of users (#98)
 * Remove redundant print statements (#97)
 * Request ID and trace ID should be visible on the console for errors as well (#96)
 * Update sample policy as per token profile update changes (#95)
 * Update CLI name from tenantclt to inteltrustauthority (#93)
 * Update the headers for request and trace id (#94)
 * cassini-9466-Go version update to 1.20.6 (#91)
 * Add retry logic to client in tenant CLI (#92)
 * Add request-id optional parameter for each command (#90)

- Override build date with SOURCE_DATE_EPOCH (bsc#1047218)");

  script_tag(name:"affected", value:"'amber-cli' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"amber-cli", rpm:"amber-cli~1.13.1+git20250329.c2e3bb8~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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
