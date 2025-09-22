# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1123.1");
  script_cve_id("CVE-2018-14779", "CVE-2018-14780");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-22 18:26:11 +0000 (Mon, 22 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1123-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191123-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yubico-piv-tool' package(s) announced via the SUSE-SU-2019:1123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yubico-piv-tool fixes the following issues:

Security issues fixed:
Fixed an buffer overflow and an out of bounds memory read in
 ykpiv_transfer_data(), which could be triggered by a malicious token.
 (CVE-2018-14779, bsc#1104809, YSA-2018-03)

Fixed an buffer overflow and an out of bounds memory read in
 _ykpiv_fetch_object(), which could be triggered by a malicious token.
 (CVE-2018-14780, bsc#1104811, YSA-2018-03)");

  script_tag(name:"affected", value:"'yubico-piv-tool' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-1", rpm:"libykcs11-1~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-1-debuginfo", rpm:"libykcs11-1-debuginfo~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-devel", rpm:"libykcs11-devel~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv-devel", rpm:"libykpiv-devel~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1", rpm:"libykpiv1~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1-debuginfo", rpm:"libykpiv1-debuginfo~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool", rpm:"yubico-piv-tool~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debuginfo", rpm:"yubico-piv-tool-debuginfo~1.5.0~3.3.33", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debugsource", rpm:"yubico-piv-tool-debugsource~1.5.0~3.3.33", rls:"SLES15.0"))) {
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
