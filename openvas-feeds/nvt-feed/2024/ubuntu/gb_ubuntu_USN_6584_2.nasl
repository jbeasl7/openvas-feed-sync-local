# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6584.2");
  script_cve_id("CVE-2021-33912", "CVE-2021-33913");
  script_tag(name:"creation_date", value:"2024-02-22 04:08:51 +0000 (Thu, 22 Feb 2024)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-26 17:40:12 +0000 (Wed, 26 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-6584-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6584-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6584-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libspf2' package(s) announced via the USN-6584-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6584-1 fixed several vulnerabilities in Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. This update provides the corresponding updates for
CVE-2021-33912 and CVE-2021-33913 in Ubuntu 16.04 LTS.

We apologize for the inconvenience.

Original advisory details:

 Philipp Jeitner and Haya Shulman discovered that Libspf2 incorrectly handled
 certain inputs. If a user or an automated system were tricked into opening a
 specially crafted input file, a remote attacker could possibly use this issue
 to cause a denial of service or execute arbitrary code. (CVE-2021-20314)

 It was discovered that Libspf2 incorrectly handled certain inputs. If a user or
 an automated system were tricked into opening a specially crafted input file, a
 remote attacker could possibly use this issue to cause a denial of service or
 execute arbitrary code. This issue only affected Ubuntu 18.04 LTS and
 Ubuntu 20.04 LTS. (CVE-2021-33912, CVE-2021-33913)");

  script_tag(name:"affected", value:"'libspf2' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmail-spf-xs-perl", ver:"1.2.10-6ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspf2-2", ver:"1.2.10-6ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspf2-dev", ver:"1.2.10-6ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spfquery", ver:"1.2.10-6ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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
