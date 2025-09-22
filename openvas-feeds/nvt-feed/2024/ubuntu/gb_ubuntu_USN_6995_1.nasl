# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6995.1");
  script_cve_id("CVE-2024-7519", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7529", "CVE-2024-8381", "CVE-2024-8382", "CVE-2024-8384");
  script_tag(name:"creation_date", value:"2024-09-10 04:09:09 +0000 (Tue, 10 Sep 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:50:28 +0000 (Wed, 04 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-6995-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6995-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6995-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-6995-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass security restrictions, cross-site
tracing, or execute arbitrary code. (CVE-2024-7521, CVE-2024-7526,
CVE-2024-7527, CVE-2024-7529, CVE-2024-8382)

It was discovered that Thunderbird did not properly manage certain memory
operations when processing graphics shared memory. An attacker could
potentially exploit this issue to escape the sandbox. (CVE-2024-7519)

Irvan Kurniawan discovered that Thunderbird did not properly check an
attribute value in the editor component, leading to an out-of-bounds read
vulnerability. An attacker could possibly use this issue to cause a denial
of service or expose sensitive information. (CVE-2024-7522)

Rob Wu discovered that Thunderbird did not properly check permissions when
creating a StreamFilter. An attacker could possibly use this issue to
modify response body of requests on any site using a web extension.
(CVE-2024-7525)

Nils Bars discovered that Thunderbird contained a type confusion
vulnerability when performing certain property name lookups. An attacker
could potentially exploit this issue to cause a denial of service, or
execute arbitrary code. (CVE-2024-8381)

It was discovered that Thunderbird did not properly manage memory during
garbage collection. An attacker could potentially exploit this issue to
cause a denial of service, or execute arbitrary code. (CVE-2024-8384)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.15.0+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.15.0+build1-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
