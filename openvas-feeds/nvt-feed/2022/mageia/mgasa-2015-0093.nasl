# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0093");
  script_cve_id("CVE-2015-2172");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0093.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15402");
  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/1056");
  script_xref(name:"URL", value:"https://www.dokuwiki.org/changes#release_2014-09-29c_hrun");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dokuwiki' package(s) announced via the MGASA-2015-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dokuwiki package fixes security vulnerability:

DokuWiki before 20140929c has a security issue in the ACL plugins remote API
component. The plugin failed to check for superuser permissions before
executing ACL addition or deletion. This means everybody with permissions to
call the XMLRPC API also had permissions to set up their own ACL rules and thus
circumventing any existing rules (CVE-2015-2172).");

  script_tag(name:"affected", value:"'dokuwiki' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"dokuwiki", rpm:"dokuwiki~20140929~1.3.mga4", rls:"MAGEIA4"))) {
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
