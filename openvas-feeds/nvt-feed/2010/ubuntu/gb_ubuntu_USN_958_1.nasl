# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840470");
  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_tag(name:"creation_date", value:"2010-07-30 13:25:34 +0000 (Fri, 30 Jul 2010)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:26:59 +0000 (Sat, 03 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-958-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-958-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-958-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-958-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in the browser engine of Thunderbird. If a
user were tricked into viewing malicious content, a remote attacker could
use this to crash Thunderbird or possibly run arbitrary code as the user
invoking the program. (CVE-2010-1211, CVE-2010-1212)

An integer overflow was discovered in how Thunderbird processed CSS values.
An attacker could exploit this to crash Thunderbird or possibly run
arbitrary code as the user invoking the program. (CVE-2010-2752)

An integer overflow was discovered in how Thunderbird interpreted the XUL
element. If a user were tricked into viewing malicious content, a remote
attacker could use this to crash Thunderbird or possibly run arbitrary code
as the user invoking the program. (CVE-2010-2753)

Aki Helin discovered that libpng did not properly handle certain malformed
PNG images. If a user were tricked into opening a crafted PNG file, an
attacker could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2010-1205)

Yosuke Hasegawa discovered that the same-origin check in Thunderbird could
be bypassed by utilizing the importScripts Web Worker method. If a user
were tricked into viewing malicious content, an attacker could exploit this
to read data from other domains. (CVE-2010-1213)

Chris Evans discovered that Thunderbird did not properly process improper
CSS selectors. If a user were tricked into viewing malicious content, an
attacker could exploit this to read data from other domains.
(CVE-2010-0654)

Soroush Dalili discovered that Thunderbird did not properly handle script
error output. An attacker could use this to access URL parameters from
other domains. (CVE-2010-2754)");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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
