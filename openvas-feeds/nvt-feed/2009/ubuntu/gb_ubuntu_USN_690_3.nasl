# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840233");
  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5511", "CVE-2008-5512");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-690-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-690-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-690-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-690-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in the browser engine. These problems could allow
an attacker to crash the browser and possibly execute arbitrary code with user
privileges. (CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Firefox could be
bypassed by utilizing XBL-bindings. An attacker could exploit this to read data
from other domains. (CVE-2008-5503)

Marius Schilder discovered that Firefox did not properly handle redirects to
an outside domain when an XMLHttpRequest was made to a same-origin resource.
It's possible that sensitive information could be revealed in the
XMLHttpRequest response. (CVE-2008-5506)

Chris Evans discovered that Firefox did not properly protect a user's data when
accessing a same-domain Javascript URL that is redirected to an unparsable
Javascript off-site resource. If a user were tricked into opening a malicious
website, an attacker may be able to steal a limited amount of private data.
(CVE-2008-5507)

Several flaws were discovered in the Javascript engine. If a user were tricked
into opening a malicious website, an attacker could exploit this to execute
arbitrary Javascript code within the context of another website or with chrome
privileges. (CVE-2008-5511, CVE-2008-5512)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
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
