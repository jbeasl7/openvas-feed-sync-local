# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64320");
  script_cve_id("CVE-2007-3215", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5153", "CVE-2008-5432", "CVE-2008-5619", "CVE-2008-6124", "CVE-2009-0499", "CVE-2009-0500", "CVE-2009-0501", "CVE-2009-0502", "CVE-2009-1171", "CVE-2009-1669");
  script_tag(name:"creation_date", value:"2009-06-29 22:29:55 +0000 (Mon, 29 Jun 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-791-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-791-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-791-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the USN-791-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thor Larholm discovered that PHPMailer, as used by Moodle, did not
correctly escape email addresses. A local attacker with direct access
to the Moodle database could exploit this to execute arbitrary commands
as the web server user. (CVE-2007-3215)

Nigel McNie discovered that fetching https URLs did not correctly escape
shell meta-characters. An authenticated remote attacker could execute
arbitrary commands as the web server user, if curl was installed and
configured. (CVE-2008-4796, MSA-09-0003)

It was discovered that Smarty (also included in Moodle), did not
correctly filter certain inputs. An authenticated remote attacker could
exploit this to execute arbitrary PHP commands as the web server user.
(CVE-2008-4810, CVE-2008-4811, CVE-2009-1669)

It was discovered that the unused SpellChecker extension in Moodle did not
correctly handle temporary files. If the tool had been locally modified,
it could be made to overwrite arbitrary local files via symlinks.
(CVE-2008-5153)

Mike Churchward discovered that Moodle did not correctly filter Wiki page
titles in certain areas. An authenticated remote attacker could exploit
this to cause cross-site scripting (XSS), which could be used to modify
or steal confidential data of other users within the same web domain.
(CVE-2008-5432, MSA-08-0022)

It was discovered that the HTML sanitizer, 'Login as' feature, and logging
in Moodle did not correctly handle certain inputs. An authenticated
remote attacker could exploit this to generate XSS, which could be used
to modify or steal confidential data of other users within the same
web domain. (CVE-2008-5619, CVE-2009-0500, CVE-2009-0502, MSA-08-0026,
MSA-09-0004, MSA-09-0007)

It was discovered that the HotPot module in Moodle did not correctly
filter SQL inputs. An authenticated remote attacker could execute
arbitrary SQL commands as the moodle database user, leading to a loss
of privacy or denial of service. (CVE-2008-6124, MSA-08-0010)

Kevin Madura discovered that the forum actions and messaging settings
in Moodle were not protected from cross-site request forgery (CSRF).
If an authenticated user were tricked into visiting a malicious
website while logged into Moodle, a remote attacker could change the
user's configurations or forum content. (CVE-2009-0499, MSA-09-0008,
MSA-08-0023)

Daniel Cabezas discovered that Moodle would leak usernames from the
Calendar Export tool. A remote attacker could gather a list of users,
leading to a loss of privacy. (CVE-2009-0501, MSA-09-0006)

Christian Eibl discovered that the TeX filter in Moodle allowed any
function to be used. An authenticated remote attacker could post
a specially crafted TeX formula to execute arbitrary TeX functions,
potentially reading any file accessible to the web server user, leading
to a loss of privacy. (CVE-2009-1171, MSA-09-0009)

Johannes Kuhn discovered that Moodle did not correctly validate user
permissions when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'moodle' package(s) on Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.8.2-1ubuntu4.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.8.2-1.2ubuntu2.1", rls:"UBUNTU8.10"))) {
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
