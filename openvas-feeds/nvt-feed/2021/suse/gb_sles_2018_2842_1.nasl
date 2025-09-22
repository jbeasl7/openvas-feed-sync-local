# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2842.1");
  script_cve_id("CVE-2017-10790", "CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 14:27:38 +0000 (Wed, 12 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2842-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2842-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182842-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105460");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004593.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2018:2842-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

Security issues fixed:

- Improved mitigations against Lucky 13 class of attacks
 - 'Just in Time' PRIME + PROBE cache-based side channel attack can lead to plaintext recovery (CVE-2018-10846, bsc#1105460)
 - HMAC-SHA-384 vulnerable to Lucky thirteen attack due to use of wrong constant (CVE-2018-10845, bsc#1105459)
 - HMAC-SHA-256 vulnerable to Lucky thirteen attack due to not enough dummy function calls (CVE-2018-10844, bsc#1105437)
- The _asn1_check_identifier function in Libtasn1 caused a NULL pointer dereference and crash (CVE-2017-10790, bsc#1047002)");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.3.27~3.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-openssl27", rpm:"libgnutls-openssl27~3.3.27~3.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls28", rpm:"libgnutls28~3.3.27~3.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls28-32bit", rpm:"libgnutls28-32bit~3.3.27~3.3.1", rls:"SLES12.0SP3"))) {
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
