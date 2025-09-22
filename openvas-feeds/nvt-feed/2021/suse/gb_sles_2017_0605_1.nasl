# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0605.1");
  script_cve_id("CVE-2016-2108", "CVE-2016-7056", "CVE-2016-8610");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 12:32:16 +0000 (Fri, 06 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0605-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0605-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170605-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984663");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002678.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2017:0605-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for compat-openssl098 fixes the following issues contained in the OpenSSL Security Advisory [26 Jan 2017] (bsc#1021641)

Security issues fixed:
- CVE-2016-7056: A local ECSDA P-256 timing attack that might have allowed key recovery was fixed (bsc#1019334)
- CVE-2016-8610: A remote denial of service in SSL alert handling was fixed (bsc#1005878)
- degrade 3DES to MEDIUM in SSL2 (bsc#1001912)
- CVE-2016-2108: Added a missing commit for CVE-2016-2108, fixing the negative zero handling in the ASN.1 decoder (bsc#1004499)

Bugs fixed:
- fix crash in openssl speed (bsc#1000677)
- don't attempt session resumption if no ticket is present and session
 ID length is zero (bsc#984663)");

  script_tag(name:"affected", value:"'compat-openssl098' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~105.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~105.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~105.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~105.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~105.1", rls:"SLES12.0"))) {
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
