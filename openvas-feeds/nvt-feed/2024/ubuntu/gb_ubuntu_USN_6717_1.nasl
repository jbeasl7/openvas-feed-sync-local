# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6717.1");
  script_cve_id("CVE-2023-5388", "CVE-2024-0743", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614", "CVE-2024-2616");
  script_tag(name:"creation_date", value:"2024-03-27 04:09:51 +0000 (Wed, 27 Mar 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:47:29 +0000 (Tue, 25 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6717-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6717-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-6717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass security restrictions, cross-site
tracing, or execute arbitrary code. (CVE-2024-0743, CVE-2024-2611,
CVE-2024-2614)

Hubert Kario discovered that Thunderbird had a timing side-channel when
performing RSA decryption. A remote attacker could possibly use this
issue to recover sensitive information. (CVE-2023-5388)

Gary Kwong discovered that Thunderbird incorrectly updated return
registers for JIT code on Armv7-A systems. An attacker could potentially
exploit this issue to execute arbitrary code. (CVE-2024-2607)

Ronald Crane discovered that Thunderbird did not properly manage memory
during character encoding. An attacker could potentially exploit this
issue to cause a denial of service. (CVE-2024-2608)

Georg Felber and Marco Squarcina discovered that Thunderbird incorrectly
handled html and body tags. An attacker who was able to inject markup into
a page otherwise protected by a Content Security Policy may have been able
obtain sensitive information. (CVE-2024-2610)

Ronald Crane discovered a use-after-free in Thunderbird when handling code
in SafeRefPtr. An attacker could potentially exploit this issue to cause a
denial of service, or execute arbitrary code. (CVE-2024-2612)

Ryan VanderMeulen and Dan Minor discovered that Thunderbird did not
properly manage memory conditions in ICU. An attacker could potentially
exploit this issue to cause a denial of service. (CVE-2024-2616)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.9.0+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.9.0+build1-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.9.0+build1-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
