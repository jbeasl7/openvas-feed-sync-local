# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856130");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-29040");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-05-13 01:00:44 +0000 (Mon, 13 May 2024)");
  script_name("openSUSE: Security Advisory for tpm2 (SUSE-SU-2024:1605-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1605-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NQB7GA33FZRMPC5SNOUTSV5S2KVNDQEJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2'
  package(s) announced via the SUSE-SU-2024:1605-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tpm2-0-tss fixes the following issues:

  * CVE-2024-29040: Fixed quote data validation by Fapi_VerifyQuote
      (bsc#1223690).

  ##");

  script_tag(name:"affected", value:"'tpm2' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0", rpm:"libtss2-sys0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi0-debuginfo", rpm:"libtss2-fapi0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-debuginfo", rpm:"libtss2-sys0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi0", rpm:"libtss2-fapi0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-32bit", rpm:"libtss2-sys0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-32bit-debuginfo", rpm:"libtss2-sys0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit-debuginfo", rpm:"libtss2-tcti-device0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit", rpm:"libtss2-esys0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit-debuginfo", rpm:"libtss2-mu0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit-debuginfo", rpm:"libtss2-esys0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit", rpm:"libtss2-mu0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit-debuginfo", rpm:"libtss2-tcti-mssim0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-64bit-debuginfo", rpm:"libtss2-sys0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit", rpm:"libtss2-tcti-mssim0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit", rpm:"libtss2-tcti-device0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-64bit", rpm:"libtss2-sys0-64bit~2.4.5~150300.3.9.1##", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0", rpm:"libtss2-sys0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi0-debuginfo", rpm:"libtss2-fapi0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-debuginfo", rpm:"libtss2-sys0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi0", rpm:"libtss2-fapi0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-32bit", rpm:"libtss2-sys0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-32bit-debuginfo", rpm:"libtss2-sys0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit-debuginfo", rpm:"libtss2-tcti-device0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit", rpm:"libtss2-esys0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit-debuginfo", rpm:"libtss2-mu0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit-debuginfo", rpm:"libtss2-esys0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit", rpm:"libtss2-mu0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit-debuginfo", rpm:"libtss2-tcti-mssim0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-64bit-debuginfo", rpm:"libtss2-sys0-64bit-debuginfo~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit", rpm:"libtss2-tcti-mssim0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit", rpm:"libtss2-tcti-device0-64bit~2.4.5~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys0-64bit", rpm:"libtss2-sys0-64bit~2.4.5~150300.3.9.1##", rls:"openSUSELeap15.3"))) {
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
