# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131202");
  script_cve_id("CVE-2016-1498", "CVE-2016-1499", "CVE-2016-1500");
  script_tag(name:"creation_date", value:"2016-02-02 05:44:19 +0000 (Tue, 02 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-11 21:17:12 +0000 (Mon, 11 Jan 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0040");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0040.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17620");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-January/176017.html");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-001");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-002");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-003");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud' package(s) announced via the MGASA-2016-0040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Cross-site scripting (XSS) vulnerability in the OCS discovery provider
in ownCloud Server before 8.0.10 allows remote attackers to inject
arbitrary web script or HTML via the URL resulting in a reflected
Cross-Site-Scripting (CVE-2016-1498).

ownCloud Server before 8.0.10 allows remote authenticated users to obtain
sensitive information from a directory listing and possibly cause a denial
of service (CPU consumption) via the force parameter to
index.php/apps/files/ajax/scan.php (CVE-2015-1499).

ownCloud Server before 8.0.10, when the 'file_versions' application is
enabled, does not properly check the return value of getOwner, which
allows remote authenticated users to read the files with names starting
with '.v' and belonging to a sharing user by leveraging an incoming share
(CVE-2016-1500).");

  script_tag(name:"affected", value:"'owncloud' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~8.0.10~1.mga5", rls:"MAGEIA5"))) {
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
