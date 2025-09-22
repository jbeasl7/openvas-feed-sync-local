# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5956.2");
  script_cve_id("CVE-2017-11503");
  script_tag(name:"creation_date", value:"2023-03-16 04:11:27 +0000 (Thu, 16 Mar 2023)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-25 15:03:18 +0000 (Tue, 25 Jul 2017)");

  script_name("Ubuntu: Security Advisory (USN-5956-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5956-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5956-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libphp-phpmailer' package(s) announced via the USN-5956-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5956-1 fixed vulnerabilities in PHPMailer. It was discovered that the
fix for CVE-2017-11503 was incomplete. This update fixes the problem.

Original advisory details:

 Dawid Golunski discovered that PHPMailer was not properly escaping user
 input data used as arguments to functions executed by the system shell. An
 attacker could possibly use this issue to execute arbitrary code. This
 issue only affected Ubuntu 16.04 ESM. (CVE-2016-10033, CVE-2016-10045)

 It was discovered that PHPMailer was not properly escaping characters
 in certain fields of the code_generator.php example code. An attacker
 could possibly use this issue to conduct cross-site scripting (XSS)
 attacks. This issue was only fixed in Ubuntu 16.04 ESM and Ubuntu 18.04
 ESM. (CVE-2017-11503)

 Yongxiang Li discovered that PHPMailer was not properly converting
 relative paths provided as user input when adding attachments to messages,
 which could lead to relative image URLs being treated as absolute local
 file paths and added as attachments. An attacker could possibly use this
 issue to access unauthorized resources and expose sensitive information.
 This issue only affected Ubuntu 16.04 ESM. (CVE-2017-5223)

 Sehun Oh discovered that PHPMailer was not properly processing untrusted
 non-local file attachments, which could lead to an object injection. An
 attacker could possibly use this issue to execute arbitrary code. This
 issue only affected Ubuntu 16.04 ESM. (CVE-2018-19296)

 Elar Lang discovered that PHPMailer was not properly escaping file
 attachment names, which could lead to a misinterpretation of file types
 by entities processing the message. An attacker could possibly use this
 issue to bypass attachment filters. This issue was only fixed in Ubuntu
 16.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-13625)

 It was discovered that PHPMailer was not properly handling callables in
 its validateAddress function, which could result in untrusted code being
 called should the global namespace contain a function called 'php'. An
 attacker could possibly use this issue to execute arbitrary code. This
 issue was only fixed in Ubuntu 20.04 ESM and Ubuntu 22.04 ESM.
 (CVE-2021-3603)");

  script_tag(name:"affected", value:"'libphp-phpmailer' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libphp-phpmailer", ver:"5.2.14+dfsg-1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libphp-phpmailer", ver:"5.2.14+dfsg-2.3+deb9u2ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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
