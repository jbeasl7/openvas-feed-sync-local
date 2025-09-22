# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3629.1");
  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16424", "CVE-2018-16425", "CVE-2018-16426", "CVE-2018-16427");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-05 21:09:13 +0000 (Mon, 05 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3629-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183629-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the SUSE-SU-2018:3629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following security issues:
CVE-2018-16391: Fixed a denial of service when handling responses from a
 Muscle Card (bsc#1106998)

CVE-2018-16392: Fixed a denial of service when handling responses from a
 TCOS Card (bsc#1106999)

CVE-2018-16393: Fixed buffer overflows when handling responses from
 Gemsafe V1 Smartcards (bsc#1108318)

CVE-2018-16418: Fixed buffer overflow when handling string concatenation
 in util_acl_to_str (bsc#1107039)

CVE-2018-16419: Fixed several buffer overflows when handling responses
 from a Cryptoflex card (bsc#1107107)

CVE-2018-16420: Fixed buffer overflows when handling responses from an
 ePass 2003 Card (bsc#1107097)

CVE-2018-16421: Fixed buffer overflows when handling responses from a
 CAC Card (bsc#1107049)

CVE-2018-16422: Fixed single byte buffer overflow when handling
 responses from an esteid Card (bsc#1107038)

CVE-2018-16423: Fixed double free when handling responses from a
 smartcard (bsc#1107037)

CVE-2018-16424: Fixed double free when handling responses in read_file
 (bsc#1107036)

CVE-2018-16425: Fixed double free when handling responses from an HSM
 Card (bsc#1107035)

CVE-2018-16426: Fixed endless recursion when handling responses from an
 IAS-ECC card (bsc#1107034)

CVE-2018-16427: Fixed out of bounds reads when handling responses in
 OpenSC (bsc#1107033)");

  script_tag(name:"affected", value:"'opensc' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.18.0~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.18.0~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.18.0~3.8.1", rls:"SLES15.0"))) {
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
