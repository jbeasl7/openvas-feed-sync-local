# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885221");
  script_cve_id("CVE-2023-39999");
  script_tag(name:"creation_date", value:"2023-11-05 02:21:25 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 16:15:53 +0000 (Mon, 16 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-1adca3e938)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1adca3e938");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1adca3e938");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244113");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244115");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress' package(s) announced via the FEDORA-2023-1adca3e938 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**WordPress 6.3.2 - Maintenance and Security release**

This security and maintenance release features 19 bug fixes on Core, 22 bug fixes for the Block Editor, and 8 security fixes.

Security updates included in this release:

* Marc Montpas of Automattic for finding a potential disclosure of user email addresses.
* Marc Montpas of Automattic for finding an RCE POP Chains vulnerability.
* Rafie Muhammad and Edouard L of Patchstack along with a WordPress commissioned third-party audit for each independently identifying a XSS issue in the post link navigation block.
* Jb Audras of the WordPress Security Team and Rafie Muhammad of Patchstack for each independently discovering an issue where comments on private posts could be leaked to other users.
* John Blackbourn (WordPress Security Team), James Golovich, J.D Grimes, Numan Turle, WhiteCyberSec for each independently identifying a way for logged-in users to execute any shortcode.
* mascara7784 and a third-party security audit for identifying a XSS vulnerability in the application password screen.
* Jorge Costa of the WordPress Core Team for identifying XSS vulnerability in the footnotes block.
* s5s and raouf_maklouf for independently identifying a cache poisoning DoS vulnerability.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~6.3.2~1.fc39", rls:"FC39"))) {
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
