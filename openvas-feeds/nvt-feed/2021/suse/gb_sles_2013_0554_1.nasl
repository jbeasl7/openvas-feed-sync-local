# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0554.1");
  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0554-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130554-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2013:0554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL has been updated to fix several security issues:

 *

 CVE-2012-4929: Avoid the openssl CRIME attack by disabling SSL compression by default. Setting the environment variable 'OPENSSL_NO_DEFAULT_ZLIB' to 'no'
enables compression again.

 Please note that openssl on SUSE Linux Enterprise 10 is not built with compression support.

 *

 CVE-2013-0169: Timing attacks against TLS could be used by physically local attackers to gain access to transmitted plain text or private keymaterial. This issue is also known as the 'Lucky-13' issue.

 *

 CVE-2013-0166: A OCSP invalid key denial of service issue was fixed.

Security Issue references:

 * CVE-2013-0169
>
 * CVE-2013-0166
>");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-32bit", rpm:"openssl-32bit~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-64bit", rpm:"openssl-64bit~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-32bit", rpm:"openssl-devel-32bit~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-64bit", rpm:"openssl-devel-64bit~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-x86", rpm:"openssl-x86~0.9.8a~18.76.1", rls:"SLES10.0SP4"))) {
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
