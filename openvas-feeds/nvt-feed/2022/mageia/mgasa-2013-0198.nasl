# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0198");
  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0198");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0198.html");
  script_xref(name:"URL", value:"http://codex.wordpress.org/Version_3.5.2");
  script_xref(name:"URL", value:"http://wordpress.org/news/2013/06/wordpress-3-5-2/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10596");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=973254");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=976784");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress' package(s) announced via the MGASA-2013-0198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way Wordpress, a blog tool and
publishing platform, performed hash computation when checking password for
password protected blog posts. A remote attacker could provide a specially-
crafted input that, when processed by the password checking mechanism of
Wordpress would lead to excessive CPU consumption (CVE-2013-2173).

Inadequate SSRF protection for HTTP requests where the user can provide a
URL can allow for attacks against the intranet and other sites. This is a
continuation of work related to CVE-2013-0235, which was specific to SSRF
in pingback requests and was fixed in 3.5.1 (CVE-2013-2199).

Inadequate checking of a user's capabilities could allow them to publish
posts when their user role should not allow for it, and to assign posts to
other authors (CVE-2013-2200).

Inadequate escaping allowed an administrator to trigger a cross-site
scripting vulnerability through the uploading of media files and plugins
(CVE-2013-2201).

The processing of an oEmbed response is vulnerable to an XXE
(CVE-2013-2202).

If the uploads directory is not writable, error message data returned via
XHR will include a full path to the directory (CVE-2013-2203).

Content Spoofing in the MoxieCode (TinyMCE) MoxiePlayer project
(CVE-2013-2204).

Cross-domain XSS in SWFUpload (CVE-2013-2205).");

  script_tag(name:"affected", value:"'wordpress' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.5.2~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.5.2~1.mga3", rls:"MAGEIA3"))) {
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
