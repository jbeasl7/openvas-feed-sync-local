# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14579.1");
  script_cve_id("CVE-2019-19906");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-02 20:32:06 +0000 (Thu, 02 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14579-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014579-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159635");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/008085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl' package(s) announced via the SUSE-SU-2020:14579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cyrus-sasl fixes the following issues:

- CVE-2019-19906: Fixed an out-of-bounds write leading to unauthenticated remote denial-of-service in OpenLDAP via a malformed LDAP packet (bsc#1159635).");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1", rpm:"cyrus-sasl-openssl1~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-32bit", rpm:"cyrus-sasl-openssl1-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-crammd5", rpm:"cyrus-sasl-openssl1-crammd5~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-crammd5-32bit", rpm:"cyrus-sasl-openssl1-crammd5-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-crammd5-x86", rpm:"cyrus-sasl-openssl1-crammd5-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-digestmd5", rpm:"cyrus-sasl-openssl1-digestmd5~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-digestmd5-32bit", rpm:"cyrus-sasl-openssl1-digestmd5-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-digestmd5-x86", rpm:"cyrus-sasl-openssl1-digestmd5-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-gssapi", rpm:"cyrus-sasl-openssl1-gssapi~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-gssapi-32bit", rpm:"cyrus-sasl-openssl1-gssapi-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-gssapi-x86", rpm:"cyrus-sasl-openssl1-gssapi-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-ntlm", rpm:"cyrus-sasl-openssl1-ntlm~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-otp", rpm:"cyrus-sasl-openssl1-otp~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-otp-32bit", rpm:"cyrus-sasl-openssl1-otp-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-otp-x86", rpm:"cyrus-sasl-openssl1-otp-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-plain", rpm:"cyrus-sasl-openssl1-plain~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-plain-32bit", rpm:"cyrus-sasl-openssl1-plain-32bit~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-plain-x86", rpm:"cyrus-sasl-openssl1-plain-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-openssl1-x86", rpm:"cyrus-sasl-openssl1-x86~2.1.22~182.26.4.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit", rpm:"cyrus-sasl-digestmd5-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit", rpm:"cyrus-sasl-otp-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit", rpm:"cyrus-sasl-sqlauxprop-32bit~2.1.22~182.26.4.1", rls:"SLES11.0SP4"))) {
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
