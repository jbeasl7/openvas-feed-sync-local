# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7318.1");
  script_cve_id("CVE-2022-23638", "CVE-2022-28959", "CVE-2022-28960", "CVE-2022-28961", "CVE-2022-37155", "CVE-2023-24258", "CVE-2023-27372", "CVE-2024-8517");
  script_tag(name:"creation_date", value:"2025-03-05 04:04:13 +0000 (Wed, 05 Mar 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-18 18:05:03 +0000 (Wed, 18 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7318-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7318-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip' package(s) announced via the USN-7318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that svg-sanitizer, vendored in SPIP, did not properly
sanitize SVG/XML content. An attacker could possibly use this issue to
perform cross site scripting. This issue only affected Ubuntu 24.10.
(CVE-2022-23638)

It was discovered that SPIP did not properly sanitize certain inputs. A
remote attacker could possibly use this issue to perform cross site
scripting. This issue only affected Ubuntu 18.04 LTS. (CVE-2022-28959)

It was discovered that SPIP did not properly sanitize certain inputs. A
remote attacker could possibly use this issue to perform PHP injection
attacks. This issue only affected Ubuntu 18.04 LTS. (CVE-2022-28960)

It was discovered that SPIP did not properly sanitize certain inputs. A
remote attacker could possibly use this issue to perform SQL injection
attacks. This issue only affected Ubuntu 18.04 LTS. (CVE-2022-28961)

It was discovered that SPIP did not properly sanitize certain inputs. A
remote authenticated attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 18.04 LTS. (CVE-2022-37155)

It was discovered that SPIP did not properly sanitize certain inputs. A
remote attacker could possibly use this issue to perform SQL injection
attacks. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2023-24258)

It was discovered that SPIP did not properly handle serialization under
certain circumstances. A remote attacker could possibly use this issue to
execute arbitrary code. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2023-27372)

It was discovered that SPIP did not properly sanitize HTTP requests. A
remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2024-8517)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 24.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.1.4-4~deb9u5ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.7-1ubuntu0.1+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"4.3.1+dfsg-1ubuntu0.1", rls:"UBUNTU24.10"))) {
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
