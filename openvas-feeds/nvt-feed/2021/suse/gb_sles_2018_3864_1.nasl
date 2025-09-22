# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3864.1");
  script_cve_id("CVE-2016-8610", "CVE-2018-0734", "CVE-2018-0737", "CVE-2018-5407");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:44:24 +0000 (Fri, 26 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3864-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3864-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183864-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113652");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-November/004873.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2018:3864-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl fixes the following issues:

Security issues fixed:

- CVE-2018-0734: Fixed timing vulnerability in DSA signature generation (bsc#1113652).
- CVE-2018-5407: Fixed elliptic curve scalar multiplication timing attack defenses (bsc#1113534).
- CVE-2018-0737: Corrected the current error detection of the current fix (bsc#1106197).
- CVE-2016-8610: Adjusted current fix and add missing error string (bsc#1110018).
- Add missing timing side channel patch for DSA signature generation (bsc#1113742).
- Fixed the 'One and Done' side-channel attack on RSA (bsc#1104789).

Non-security issues fixed:

- Added openssl(cli) so that the packages that required the openssl binary can require this instead of the new openssl meta package (bsc#1101470).");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~1.0.1i~54.20.1", rls:"SLES12.0SP1"))) {
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
