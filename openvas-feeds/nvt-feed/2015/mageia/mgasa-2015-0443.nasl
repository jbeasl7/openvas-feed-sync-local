# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131126");
  script_cve_id("CVE-2015-5602");
  script_tag(name:"creation_date", value:"2015-11-11 07:58:15 +0000 (Wed, 11 Nov 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0443");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0443.html");
  script_xref(name:"URL", value:"http://www.sudo.ws/stable.html#1.8.15");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17117");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the MGASA-2015-0443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An unauthorized privilege escalation was found in sudoedit in sudo before
1.8.15 when a user is granted with root access to modify a particular file
that could be located in a subset of directories. It seems that sudoedit
does not check the full path if a wildcard is used twice
(e.g. /home/*/*/file.txt), allowing a malicious user to replace the
file.txt real file with a symbolic link to a different location
(e.g. /etc/shadow), which results in unauthorized access (CVE-2015-5602).

The sudo package has been updated to version 1.8.15, which fixes this
issue, and also includes many other bug fixes and changes. See the
upstream change log for details.");

  script_tag(name:"affected", value:"'sudo' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.15~1.mga5", rls:"MAGEIA5"))) {
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
