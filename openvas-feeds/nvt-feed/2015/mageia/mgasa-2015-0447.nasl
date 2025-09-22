# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131132");
  script_cve_id("CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2015-11-17 09:00:00 +0000 (Tue, 17 Nov 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0447");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0447.html");
  script_xref(name:"URL", value:"http://www.seamonkey-project.org/releases/seamonkey2.39/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17119");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-116/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-117/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-118/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-121/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-122/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-123/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-127/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-128/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-129/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-130/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-131/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-132/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2015-0447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 42.0 and Firefox ESR 38.x before 38.4 allow remote attackers
to cause a denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unknown vectors. (CVE-2015-4513)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 42.0 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary
code via unknown vectors. (CVE-2015-4514)

Mozilla Firefox before 42.0, when NTLM v1 is enabled for HTTP
authentication, allows remote attackers to obtain sensitive hostname
information by constructing a crafted web site that sends an NTLM request
and reads the Workstation field of an NTLM type 3 message. (CVE-2015-4515)

The Reader View implementation in Mozilla Firefox before 42.0 has an
improper whitelist, which makes it easier for remote attackers to bypass
the Content Security Policy (CSP) protection mechanism and conduct
cross-site scripting (XSS) attacks via vectors involving SVG animations and
the about:reader URL. (CVE-2015-4518)

The Add-on SDK in Mozilla Firefox before 42.0 misinterprets a 'script:
false' panel setting, which makes it easier for remote attackers to conduct
cross-site scripting (XSS) attacks via inline JavaScript code that is
executed within a third-party extension. (CVE-2015-7187)

Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 allow remote
attackers to bypass the Same Origin Policy for an IP address origin, and
conduct cross-site scripting (XSS) attacks, by appending whitespace
characters to an IP address string. (CVE-2015-7188)

Race condition in the JPEGEncoder function in Mozilla Firefox before 42.0
and Firefox ESR 38.x before 38.4 allows remote attackers to execute
arbitrary code or cause a denial of service (heap-based buffer overflow)
via vectors involving a CANVAS element and crafted JavaScript code.
(CVE-2015-7189)

Mozilla Firefox before 42.0 and Firefox ESR 38.x before 38.4 improperly
follow the CORS cross-origin request algorithm for the POST method in
situations involving an unspecified Content-Type header manipulation, which
allows remote attackers to bypass the Same Origin Policy by leveraging the
lack of a preflight-request step. (CVE-2015-7193)

Buffer underflow in libjar in Mozilla Firefox before 42.0 and Firefox ESR
38.x before 38.4 allows remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted ZIP
archive. (CVE-2015-7194)

The URL parsing implementation in Mozilla Firefox before 42.0 improperly
recognizes escaped characters in hostnames within Location headers, which
allows remote attackers to obtain sensitive information via vectors
involving a redirect. (CVE-2015-7195)

Mozilla Firefox before 42.0 and Firefox ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.39~1.mga5", rls:"MAGEIA5"))) {
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
