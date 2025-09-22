# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54528");
  script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:33:00 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-03 (OpenSSL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Three vulnerabilities have been found in OpenSSL via a commercial test
suite for the TLS protocol developed by Codenomicon Ltd.");
  script_tag(name:"solution", value:"All users are recommended to upgrade openssl to either 0.9.7d or 0.9.6m:

    # emerge sync
    # emerge -pv '>=dev-libs/openssl-0.9.7d'
    # emerge '>=dev-libs/openssl-0.9.7d'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=44941");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-libs/openssl", unaffected: make_list("ge 0.9.7d", "eq 0.9.6m"), vulnerable: make_list("le 0.9.7c"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
