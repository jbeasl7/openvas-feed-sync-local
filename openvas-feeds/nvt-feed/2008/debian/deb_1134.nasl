# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57203");
  script_cve_id("CVE-2006-1729", "CVE-2006-1942", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1134-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1134-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1134");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-thunderbird' package(s) announced via the DSA-1134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla which are also present in Mozilla Thunderbird. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-1942

Eric Foley discovered that a user can be tricked to expose a local file to a remote attacker by displaying a local file as image in connection with other vulnerabilities. [MFSA-2006-39]

CVE-2006-2775

XUL attributes are associated with the wrong URL under certain circumstances, which might allow remote attackers to bypass restrictions. [MFSA-2006-35]

CVE-2006-2776

Paul Nickerson discovered that content-defined setters on an object prototype were getting called by privileged user interface code, and 'moz_bug_r_a4' demonstrated that the higher privilege level could be passed along to the content-defined attack code. [MFSA-2006-37]

CVE-2006-2777

A vulnerability allows remote attackers to execute arbitrary code and create notifications that are executed in a privileged context. [MFSA-2006-43]

CVE-2006-2778

Mikolaj Habryn discovered a buffer overflow in the crypto.signText function that allows remote attackers to execute arbitrary code via certain optional Certificate Authority name arguments. [MFSA-2006-38]

CVE-2006-2779

Mozilla team members discovered several crashes during testing of the browser engine showing evidence of memory corruption which may also lead to the execution of arbitrary code. This problem has only partially been corrected. [MFSA-2006-32]

CVE-2006-2780

An integer overflow allows remote attackers to cause a denial of service and may permit the execution of arbitrary code. [MFSA-2006-32]

CVE-2006-2781

Masatoshi Kimura discovered a double-free vulnerability that allows remote attackers to cause a denial of service and possibly execute arbitrary code via a VCard. [MFSA-2006-40]

CVE-2006-2782

Chuck McAuley discovered that a text input box can be pre-filled with a filename and then turned into a file-upload control, allowing a malicious website to steal any local file whose name they can guess. [MFSA-2006-41, MFSA-2006-23, CVE-2006-1729]

CVE-2006-2783

Masatoshi Kimura discovered that the Unicode Byte-order-Mark (BOM) is stripped from UTF-8 pages during the conversion to Unicode before the parser sees the web page, which allows remote attackers to conduct cross-site scripting (XSS) attacks. [MFSA-2006-42]

CVE-2006-2784

Paul Nickerson discovered that the fix for CVE-2005-0752 can be bypassed using nested javascript: URLs, allowing the attacker to execute privileged code. [MFSA-2005-34, MFSA-2006-36]

CVE-2006-2785

Paul Nickerson demonstrated that if an attacker could convince a user to right-click on a broken image and choose 'View Image' from the context menu then he could get JavaScript to run. [MFSA-2006-34]

CVE-2006-2786

Kazuho Oku discovered that Mozilla's lenient handling of HTTP header syntax may allow remote attackers ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.8a", rls:"DEB3.1"))) {
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
