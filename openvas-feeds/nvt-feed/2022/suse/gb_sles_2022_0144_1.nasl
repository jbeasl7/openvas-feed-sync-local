# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0144.1");
  script_cve_id("CVE-2021-4122");
  script_tag(name:"creation_date", value:"2022-01-21 03:23:01 +0000 (Fri, 21 Jan 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 14:28:45 +0000 (Mon, 29 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0144-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220144-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cryptsetup' package(s) announced via the SUSE-SU-2022:0144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cryptsetup fixes the following issues:

CVE-2021-4122: Fixed possible attacks against data confidentiality
 through LUKS2 online reencryption extension crash recovery (bsc#1194469).");

  script_tag(name:"affected", value:"'cryptsetup' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE MicroOS 5.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"cryptsetup", rpm:"cryptsetup~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cryptsetup-debuginfo", rpm:"cryptsetup-debuginfo~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cryptsetup-debugsource", rpm:"cryptsetup-debugsource~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cryptsetup-lang", rpm:"cryptsetup-lang~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup-devel", rpm:"libcryptsetup-devel~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12", rpm:"libcryptsetup12~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12-32bit", rpm:"libcryptsetup12-32bit~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12-32bit-debuginfo", rpm:"libcryptsetup12-32bit-debuginfo~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12-debuginfo", rpm:"libcryptsetup12-debuginfo~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12-hmac", rpm:"libcryptsetup12-hmac~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptsetup12-hmac-32bit", rpm:"libcryptsetup12-hmac-32bit~2.3.7~150300.3.5.1", rls:"SLES15.0SP3"))) {
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
