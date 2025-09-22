# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0548.1");
  script_cve_id("CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0548-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0548-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150548-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl097g' package(s) announced via the SUSE-SU-2015:0548-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL has been updated to fix various security issues:

 *

 CVE-2015-0286: A segmentation fault in ASN1_TYPE_cmp was fixed that could be exploited by attackers when e.g. client authentication is used.
This could be exploited over SSL connections.

 *

 CVE-2015-0287: A ASN.1 structure reuse memory corruption was fixed.
This problem can not be exploited over regular SSL connections, only if specific client programs use specific ASN.1 routines.

 *

 CVE-2015-0288: A X509_to_X509_REQ NULL pointer dereference was fixed, which could lead to crashes. This function is not commonly used,
and not reachable over SSL methods.

 *

 CVE-2015-0289: Several PKCS7 NULL pointer dereferences were fixed,
which could lead to crashes of programs using the PKCS7 APIs. The SSL apis do not use those by default.

 *

 CVE-2015-0292: Various issues in base64 decoding were fixed, which could lead to crashes with memory corruption, for instance by using attacker supplied PEM data.

 *

 CVE-2015-0293: Denial of service via reachable assert in SSLv2 servers, could be used by remote attackers to terminate the server process. Note that this requires SSLv2 being allowed, which is not the default.");

  script_tag(name:"affected", value:"'compat-openssl097g' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~13.29.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~13.29.1", rls:"SLES10.0SP4"))) {
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
