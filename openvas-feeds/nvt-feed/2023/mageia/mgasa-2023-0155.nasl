# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0155");
  script_cve_id("CVE-2023-28447");
  script_tag(name:"creation_date", value:"2023-04-24 04:13:19 +0000 (Mon, 24 Apr 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-04 23:36:39 +0000 (Tue, 04 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0155.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31794");
  script_xref(name:"URL", value:"https://github.com/smarty-php/smarty/releases/tag/v4.3.0");
  script_xref(name:"URL", value:"https://github.com/smarty-php/smarty/releases/tag/v4.3.1");
  script_xref(name:"URL", value:"https://github.com/smarty-php/smarty/security/advisories/GHSA-7j98-h7fp-4vwj");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HSAUM3YHWHO4UCJXRGRLQGPJAO3MFOZZ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-smarty' package(s) announced via the MGASA-2023-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross site scripting vulnerability in Javascript escaping.
(CVE-2023-28447)

Additional bug fixes included. See referenced release notes for details.");

  script_tag(name:"affected", value:"'php-smarty' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"php-smarty", rpm:"php-smarty~4.3.1~1.mga8", rls:"MAGEIA8"))) {
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
