# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840493");
  script_cve_id("CVE-2010-2760", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_tag(name:"creation_date", value:"2010-09-10 12:21:00 +0000 (Fri, 10 Sep 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-978-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-978-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several dangling pointer vulnerabilities were discovered in Thunderbird. An
attacker could exploit this to crash Thunderbird or possibly run arbitrary
code as the user invoking the program. (CVE-2010-2760, CVE-2010-2767,
CVE-2010-3167)

It was discovered that the XPCSafeJSObjectWrapper (SJOW) security wrapper
did not always honor the same-origin policy. If JavaScript was enabled, an
attacker could exploit this to run untrusted JavaScript from other domains.
(CVE-2010-2763)

Matt Haggard discovered that Thunderbird did not honor same-origin policy
when processing the statusText property of an XMLHttpRequest object. If a
user were tricked into viewing a malicious site, a remote attacker could
use this to gather information about servers on internal private networks.
(CVE-2010-2764)

Chris Rohlf discovered an integer overflow when Thunderbird processed the
HTML frameset element. If a user were tricked into viewing a malicious
site, a remote attacker could use this to crash Thunderbird or possibly run
arbitrary code as the user invoking the program. (CVE-2010-2765)

Several issues were discovered in the browser engine. If a user were
tricked into viewing a malicious site, a remote attacker could use this to
crash Thunderbird or possibly run arbitrary code as the user invoking the
program. (CVE-2010-2766, CVE-2010-3168)

David Huang and Collin Jackson discovered that the <object> tag could
override the charset of a framed HTML document in another origin. An
attacker could utilize this to perform cross-site scripting attacks.
(CVE-2010-2768)

Paul Stone discovered that with designMode enabled an HTML selection
containing JavaScript could be copied and pasted into a document and have
the JavaScript execute within the context of the site where the code was
dropped. If JavaScript was enabled, an attacker could utilize this to
perform cross-site scripting attacks. (CVE-2010-2769)

A buffer overflow was discovered in Thunderbird when processing text runs.
If a user were tricked into viewing a malicious site, a remote attacker
could use this to crash Thunderbird or possibly run arbitrary code as the
user invoking the program. (CVE-2010-3166)

Peter Van der Beken, Jason Oster, Jesse Ruderman, Igor Bukanov, Jeff
Walden, Gary Kwong and Olli Pettay discovered several flaws in the
browser engine. If a user were tricked into viewing a malicious site, a
remote attacker could use this to crash Thunderbird or possibly run
arbitrary code as the user invoking the program. (CVE-2010-3169)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"3.0.7+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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
