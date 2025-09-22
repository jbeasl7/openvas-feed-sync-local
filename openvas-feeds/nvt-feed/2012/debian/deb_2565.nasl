# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72533");
  script_cve_id("CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4182", "CVE-2012-4186", "CVE-2012-4188");
  script_tag(name:"creation_date", value:"2012-10-29 14:19:44 +0000 (Mon, 29 Oct 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2565-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2565-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2565");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-2565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Iceweasel, Debian's version of the Mozilla Firefox web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3982: Multiple unspecified vulnerabilities in the browser engine allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors.

CVE-2012-3986: Iceweasel does not properly restrict calls to DOMWindowUtils methods, which allows remote attackers to bypass intended access restrictions via crafted JavaScript code.

CVE-2012-3990: A Use-after-free vulnerability in the IME State Manager implementation allows remote attackers to execute arbitrary code via unspecified vectors, related to the nsIContent::GetNameSpaceID function.

CVE-2012-3991: Iceweasel does not properly restrict JSAPI access to the GetProperty function, which allows remote attackers to bypass the Same Origin Policy and possibly have unspecified other impact via a crafted web site.

CVE-2012-4179: A use-after-free vulnerability in the nsHTMLCSSUtils::CreateCSSPropertyTxn function allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via unspecified vectors.

CVE-2012-4180: A heap-based buffer overflow in the nsHTMLEditor::IsPrevCharInNodeWhitespace function allows remote attackers to execute arbitrary code via unspecified vectors.

CVE-2012-4182: A use-after-free vulnerability in the nsTextEditRules::WillInsert function allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via unspecified vectors.

CVE-2012-4186: A heap-based buffer overflow in the nsWav-eReader::DecodeAudioData function allows remote attackers to execute arbitrary code via unspecified vectors.

CVE-2012-4188: A heap-based buffer overflow in the Convolve3x3 function allows remote attackers to execute arbitrary code via unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed in version 3.5.16-19.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 10.0.8esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"3.5.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"3.5.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs2d", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs2d-dbg", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1-dbg", ver:"1.9.1.16-19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.1.16-19", rls:"DEB6"))) {
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
