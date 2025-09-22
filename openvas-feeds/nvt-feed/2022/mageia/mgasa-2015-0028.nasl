# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0028");
  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0028)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0028");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0028.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15044");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-02/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-05/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-06/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-08/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-09/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2015-0028 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox
before 35.0, Firefox ESR 31.x before 31.4, Thunderbird before 31.4, and
SeaMonkey before 2.32 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary code via
unknown vectors. (CVE-2014-8634)

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox
before 35.0 and SeaMonkey before 2.32 allow remote attackers to cause a denial
of service (memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors. (CVE-2014-8635)

Mozilla Firefox before 35.0 and SeaMonkey before 2.32 do not properly initialize
memory for BMP images, which allows remote attackers to obtain sensitive
information from process memory via a crafted web page that triggers the
rendering of malformed BMP data within a CANVAS element. (CVE-2014-8637)

The navigator.sendBeacon implementation in Mozilla Firefox before 35.0, Firefox
ESR 31.x before 31.4, Thunderbird before 31.4, and SeaMonkey before 2.32 omits
the CORS Origin header, which allows remote attackers to bypass intended CORS
access-control checks and conduct cross-site request forgery (CSRF) attacks via
a crafted web site. (CVE-2014-8638)

Mozilla Firefox before 35.0, Firefox ESR 31.x before 31.4, Thunderbird before
31.4, and SeaMonkey before 2.32 do not properly interpret Set-Cookie headers
within responses that have a 407 (aka Proxy Authentication Required) status
code, which allows remote HTTP proxy servers to conduct session fixation attacks
by providing a cookie name that corresponds to the session cookie of the origin
server.(CVE-2014-8639)

The mozilla::dom::AudioParamTimeline::AudioNodeInputValue function in the Web
Audio API implementation in Mozilla Firefox before 35.0 and SeaMonkey before
2.32 does not properly restrict timeline operations, which allows remote
attackers to cause a denial of service (uninitialized-memory read and
application crash) via crafted API calls. (CVE-2014-8640)

Use-after-free vulnerability in the WebRTC implementation in Mozilla Firefox
before 35.0, Firefox ESR 31.x before 31.4, and SeaMonkey before 2.32 allows
remote attackers to execute arbitrary code via crafted track data.
(CVE-2014-8641)

Mozilla Firefox before 35.0 and SeaMonkey before 2.32 do not consider the
id-pkix-ocsp-nocheck extension in deciding whether to trust an OCSP responder,
which makes it easier for remote attackers to obtain sensitive information by
sniffing the network during a session in which there was an incorrect decision
to accept a compromised and revoked certificate. (CVE-2014-8642)

The XrayWrapper implementation in Mozilla Firefox before 35.0 and SeaMonkey
before 2.32 does not properly interact with a DOM object that has a named
getter, which might allow remote attackers to execute arbitrary ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.32~1.mga4", rls:"MAGEIA4"))) {
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
