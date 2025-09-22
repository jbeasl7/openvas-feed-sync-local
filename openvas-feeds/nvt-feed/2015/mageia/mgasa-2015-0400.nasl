# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131093");
  script_cve_id("CVE-2015-2180", "CVE-2015-2181", "CVE-2015-5382");
  script_tag(name:"creation_date", value:"2015-10-15 03:54:50 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-05 20:36:41 +0000 (Sun, 05 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0400)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0400");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0400.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-06/msg00062.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/07/07/2");
  script_xref(name:"URL", value:"http://trac.roundcube.net/ticket/1490261");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13056");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16249");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.0.6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the MGASA-2015-0400 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues in the DBMail driver for the password plugin,
including buffer overflows (CVE-2015-2181) and the ability for a remote
attacker to execute arbitrary shell commands as root (CVE-2015-2180).

An authenticated user can download arbitrary files from the web server
that the web server process has read access to, by uploading a vCard with
a specially crafted POST (CVE-2015-5382).

The roundcubemail package has been updated to version 1.0.6, fixing these
issues and several other bugs, however the installer is currently known
to be broken.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.0.6~1.1.mga5", rls:"MAGEIA5"))) {
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
