# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130011");
  script_cve_id("CVE-2015-0854");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:30 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 18:50:04 +0000 (Tue, 03 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0380");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0380.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/13/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16754");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shutter' package(s) announced via the MGASA-2015-0380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated shutter package fixes security vulnerability:

In the 'Shutter' screenshot application, it was discovered that using the
'Show in folder' menu option while viewing a file with a specially-crafted
path allows for arbitrary code execution with the permissions of the user
running Shutter (CVE-2015-0854).");

  script_tag(name:"affected", value:"'shutter' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"shutter", rpm:"shutter~0.93~4.1.mga5", rls:"MAGEIA5"))) {
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
