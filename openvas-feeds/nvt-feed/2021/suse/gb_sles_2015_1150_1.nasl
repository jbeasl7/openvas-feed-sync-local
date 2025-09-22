# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1150.1");
  script_cve_id("CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-06-15 15:28:25 +0000 (Mon, 15 Jun 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1150-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151150-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934493");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001464.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098' package(s) announced via the SUSE-SU-2015:1150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:

- CVE-2015-4000 (boo#931698)
 * The Logjam Attack / weakdh.org
 * reject connections with DH parameters shorter than 1024 bits
 * generates 2048-bit DH parameters by default
- CVE-2015-1788 (boo#934487)
 * Malformed ECParameters causes infinite loop
- CVE-2015-1789 (boo#934489)
 * Exploitable out-of-bounds read in X509_cmp_time
- CVE-2015-1790 (boo#934491)
 * PKCS7 crash with missing EnvelopedContent
- CVE-2015-1792 (boo#934493)
 * CMS verify infinite loop with unknown hash function
- CVE-2015-1791 (boo#933911)
 * race condition in NewSessionTicket
- CVE-2015-3216 (boo#933898)
 * Crash in ssleay_rand_bytes due to locking regression
 * modified openssl-1.0.1i-fipslocking.patch
- fix timing side channel in RSA decryption (bnc#929678)
- add ECC ciphersuites to DEFAULT (bnc#879179)
- Disable EXPORT ciphers by default (bnc#931698, comment #3)");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~78.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~78.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~78.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~78.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~78.1", rls:"SLES12.0"))) {
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
