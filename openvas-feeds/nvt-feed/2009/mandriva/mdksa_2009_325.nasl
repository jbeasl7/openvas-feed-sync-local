# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66424");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-0642", "CVE-2009-1904");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:325 (ruby)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in ruby:

ext/openssl/ossl_ocsp.c in Ruby 1.8 and 1.9 does not properly check
the return value from the OCSP_basic_verify function, which might allow
remote attackers to successfully present an invalid X.509 certificate,
possibly involving a revoked certificate (CVE-2009-0642).

The BigDecimal library in Ruby 1.8.6 before p369 and 1.8.7 before
p173 allows context-dependent attackers to cause a denial of service
(application crash) via a string argument that represents a large
number, as demonstrated by an attempted conversion to the Float data
type (CVE-2009-1904).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides a solution to these vulnerabilities.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:325");
  script_tag(name:"summary", value:"The remote host is missing an update to ruby
announced via advisory MDVSA-2009:325.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.6~5.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.6~5.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~1.8.6~5.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~1.8.6~5.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
