# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63848");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Security Advisory SUSE-SA:2009:023 (MozillaFirefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSE10\.3");
  script_tag(name:"insight", value:"The Mozilla Firefox Browser was refreshed to the current MOZILLA_1_8
branch state around fix level 2.0.0.22, backporting various security
fixes from the Firefox 3.0.8 browser version.

Security issues identified as being fixed are:
MFSA 2009-01 / CVE-2009-0352 / CVE-2009-0353: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-07 / CVE-2009-0772 / CVE-2009-0774: Mozilla developers
identified and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these crashes
showed evidence of memory corruption under certain circumstances and
we presume that with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher Georgi
Guninski reported that a website could use nsIRDFService and a
cross-domain redirect to steal arbitrary XML data from another domain,
a violation of the same-origin policy. This vulnerability could be used
by a malicious website to steal private data from users authenticated
to the redirected website.

MFSA 2009-10 / CVE-2009-0040: Google security researcher Tavis
Ormandy reported several memory safety hazards to the libpng project,
an external library used by Mozilla to render PNG images. These
vulnerabilities could be used by a malicious website to crash a
victim's browser and potentially execute arbitrary code on their
computer. libpng was upgraded to version 1.2.35 which contains fixes
for these flaws.

MFSA 2009-12 / CVE-2009-1169: Security researcher Guido Landi
discovered that a XSL stylesheet could be used to crash the browser
during a XSL transformation. An attacker could potentially use this
crash to run arbitrary code on a victim's computer.
This vulnerability was also previously reported as a stability problem
by Ubuntu community member, Andre. Ubuntu community member Michael
Rooney reported Andre's findings to Mozilla, and Mozilla community
member Martin helped reduce Andre's original test case and contributed
a patch to fix the vulnerability.");
  script_tag(name:"solution", value:"Update your system with the packages as indicated in
  the referenced security advisory.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:023");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:023.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.21post~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.21post~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
