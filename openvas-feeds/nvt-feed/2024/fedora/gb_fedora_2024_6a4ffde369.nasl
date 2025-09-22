# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.6974102102100101369");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-6a4ffde369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6a4ffde369");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6a4ffde369");
  script_xref(name:"URL", value:"https://wordpress.org/news/2024/06/wordpress-6-5-5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress' package(s) announced via the FEDORA-2024-6a4ffde369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**WordPress 6.5.5 Maintenance & Security Release**


Security updates included in this release

The security team would like to thank the following people for responsibly reporting vulnerabilities, and allowing them to be fixed in this release:

* A cross-site scripting (XSS) vulnerability affecting the HTML API reported by Dennis Snell of the WordPress Core Team, along with Alex Concha and Grzegorz (Greg) Ziolkowski of the WordPress security team.
* A cross-site scripting (XSS) vulnerability affecting the Template Part block reported independently by Rafie Muhammad of Patchstack and during a third party security audit.
* A path traversal issue affecting sites hosted on Windows reported independently by Rafie M & Edouard L of Patchstack, David Fifield, x89, apple502j, and mishre.

See also the [Upstream announcement]([link moved to references])");

  script_tag(name:"affected", value:"'wordpress' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~6.5.5~1.fc40", rls:"FC40"))) {
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
