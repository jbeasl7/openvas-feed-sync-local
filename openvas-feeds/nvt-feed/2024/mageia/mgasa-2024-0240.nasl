# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0240");
  script_cve_id("CVE-2024-38428");
  script_tag(name:"creation_date", value:"2024-06-28 04:11:20 +0000 (Fri, 28 Jun 2024)");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-08 15:05:30 +0000 (Thu, 08 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0240");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0240.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33327");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035703.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wget' package(s) announced via the MGASA-2024-0240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"url.c in GNU Wget through 1.24.5 mishandles semicolons in the userinfo
subcomponent of a URI, and thus there may be insecure behavior in which
data that was supposed to be in the userinfo subcomponent is
misinterpreted to be part of the host subcomponent. (CVE-2024-38428)");

  script_tag(name:"affected", value:"'wget' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"wget", rpm:"wget~1.21.4~1.1.mga9", rls:"MAGEIA9"))) {
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
