# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0305.1");
  script_cve_id("CVE-2014-0224", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-06-06 14:29:47 +0000 (Fri, 06 Jun 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0305-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150305-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912296");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001232.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2015:0305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openssl 0.9.8j compatibility package was updated to fix several security vulnerabilities:

CVE-2014-3570: Bignum squaring (BN_sqr) may produce incorrect results on some platforms, including x86_64.

CVE-2014-3571: Fix crash in dtls1_get_record whilst in the listen state where you get two separate reads performed - one for the header and one for the body of the handshake record.

CVE-2014-3572: Do not accept a handshake using an ephemeral ECDH ciphersuites with the server key exchange message omitted.

CVE-2014-8275: Fixed various certificate fingerprint issues

CVE-2015-0204: Only allow ephemeral RSA keys in export ciphersuites

CVE-2015-0205: OpenSSL 0.9.8j is NOT vulnerable to CVE-2015-0205 as it doesn't support DH certificates and this typo prohibits skipping of certificate verify message for sign only certificates anyway.
(This patch only fixes the wrong condition)

This update also fixes regression caused by CVE-2014-0224.patch (bnc#892403)");

  script_tag(name:"affected", value:"'compat-openssl098' package(s) on SUSE Linux Enterprise Desktop 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~70.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~70.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~70.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~70.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~70.2", rls:"SLES12.0"))) {
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
