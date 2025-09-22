# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7258.1");
  script_cve_id("CVE-2022-24728", "CVE-2023-28439", "CVE-2024-24815", "CVE-2024-24816", "CVE-2024-43411");
  script_tag(name:"creation_date", value:"2025-02-07 04:08:03 +0000 (Fri, 07 Feb 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 05:01:35 +0000 (Thu, 15 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-7258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7258-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7258-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ckeditor' package(s) announced via the USN-7258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Backhouse discovered that CKEditor did not properly sanitize HTML
content. An attacker could possibly use this issue to perform cross site
scripting and obtain sensitive information. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-24728)

It was discovered that CKEditor did not properly handle the creation of
editor instances in the Iframe Dialog and Media Embed packages. An
attacker could possibly use this issue to perform cross site scripting
and obtain sensitive information. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2023-28439)

It was discovered that CKEditor did not properly handle parsing HTML
content. An attacker could possibly use this issue to perform cross site
scripting and obtain sensitive information.
(CVE-2024-24815, CVE-2024-24816)

It was discovered that CKEditor did not properly sanitize version
notifications. An attacker could possibly use this issue to perform cross
site scripting and obtain sensitive information. This issue only affected
Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2024-43411)");

  script_tag(name:"affected", value:"'ckeditor' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.5.7+dfsg-2ubuntu0.16.04.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.5.7+dfsg-2ubuntu0.18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.12.1+dfsg-1ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.16.2+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.22.1+dfsg1-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.22.1+dfsg1-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
