# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8080.1");
  script_cve_id("CVE-2016-10211", "CVE-2017-11328", "CVE-2017-5923", "CVE-2017-5924", "CVE-2017-8294", "CVE-2017-8929", "CVE-2017-9304", "CVE-2017-9438", "CVE-2017-9465", "CVE-2018-12034", "CVE-2018-12035", "CVE-2018-19974", "CVE-2018-19975", "CVE-2018-19976", "CVE-2019-19648", "CVE-2021-3402", "CVE-2021-45429");
  script_tag(name:"creation_date", value:"2026-03-10 04:34:06 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-24 16:30:27 +0000 (Mon, 24 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-8080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8080-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8080-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yara' package(s) announced via the USN-8080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kamil Frankowicz discovered that a number of YARA's functions
generated memory exceptions when processing specially crafted
rules or files. A remote attacker could possibly use these
issues to cause YARA to crash, resulting in a denial of
service. These issues only affected Ubuntu 16.04 LTS.
(CVE-2016-10211, CVE-2017-5923, CVE-2017-5924, CVE-2017-8294,
CVE-2017-8929, CVE-2017-9304, CVE-2017-9438, CVE-2017-9465)

Jurriaan Bremer discovered that YARA's yr_object_array_set_limit()
function could result in a heap buffer overflow when scanning
specially crafted .NET files. A remote attacker could possibly use
this issue to cause YARA to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS. (CVE-2017-11328)

It was discovered that YARA's yr_execute_code() function could
cause an out-of-bounds read or write when parsing specially crafted
compiled rule files. A remote attacker could possibly use these
issues to cause YARA to crash, resulting in a denial of service.
These issues only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2018-12034, CVE-2018-12035)

It was discovered that YARA's virtual machine could be escaped in
certain instances. A remote attacker could possibly use these issues
to execute arbitrary code. These issues only affected Ubuntu 16.04
LTS and Ubuntu 18.04 LTS. (CVE-2018-19974, CVE-2018-19975,
CVE-2018-19976)

It was discovered that YARA's macho_parse_file() function would
generate an out-of-bounds memory access error when parsing a
specially crafted Mach-O file. A remote attacker could possibly use
this issue to cause YARA to crash, resulting in a denial of service,
or execute arbitrary code. This issue only affected Ubuntu 20.04 LTS.
(CVE-2019-19648)

It was discovered that YARA's macho.c implementation contained several
overflow reads, which could be triggered when parsing specially
crafted Mach-O files. A remote attacker could possibly use this issue
to cause YARA to crash, resulting in a denial of service, or to learn
sensitive information. This issue only affected Ubuntu 20.04 LTS.
(CVE-2021-3402)

It was discovered that YARA's yr_set_configuration() function could
trigger a buffer overflow when parsing specially crafted rules. A
remote attacker could possibly use this issue to cause YARA to crash,
resulting in a denial of service. This issue only affected Ubuntu
18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-45429)");

  script_tag(name:"affected", value:"'yara' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libyara3", ver:"3.4.0+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-yara", ver:"3.4.0+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-yara", ver:"3.4.0+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"yara", ver:"3.4.0+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libyara3", ver:"3.7.1-1ubuntu2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"yara", ver:"3.7.1-1ubuntu2+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libyara3", ver:"3.9.0-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"yara", ver:"3.9.0-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
