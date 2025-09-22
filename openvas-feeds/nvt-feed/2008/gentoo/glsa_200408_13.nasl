# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54643");
  script_version("2024-01-29T05:05:18+0000");
  script_cve_id("CVE-2004-0689", "CVE-2004-0690", "CVE-2004-0721");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:06:00 +0000 (Fri, 26 Jan 2024)");
  script_name("Gentoo Security Advisory GLSA 200408-13 (kde, kdebase, kdelibs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"KDE contains three security issues that can allow an attacker to compromise
system accounts, cause a Denial of Service, or spoof websites via frame
injection.");
  script_tag(name:"solution", value:"All KDE users should upgrade to the latest versions of kdelibs and kdebase:

    # emerge sync

    # emerge -pv '>=kde-base/kdebase-3.2.3-r1'
    # emerge '>=kde-base/kdebase-3.2.3-r1'

    # emerge -pv '>=kde-base/kdelibs-3.2.3-r1'
    # emerge '>=kde-base/kdelibs-3.2.3-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200408-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=60068");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20040811-1.txt");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20040811-2.txt");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20040811-3.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200408-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"kde-base/kdebase", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdelibs", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
