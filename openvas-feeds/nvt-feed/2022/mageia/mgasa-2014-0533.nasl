# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0533");
  script_cve_id("CVE-2014-9274", "CVE-2014-9275");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0533");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0533.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14783");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1170233");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrtf' package(s) announced via the MGASA-2014-0533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated unrtf package fixes security vulnerabilities:

Michal Zalewski reported an out-of-bounds memory access vulnerability in
unrtf. Processing a malformed RTF file could lead to a segfault while
accessing a pointer that may be under the attacker's control. This would
lead to a denial of service (application crash) or, potentially, the
execution of arbitrary code (CVE-2014-9274).

Hanno Bock also reported a number of other crashes in unrtf (CVE-2014-9275).");

  script_tag(name:"affected", value:"'unrtf' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"unrtf", rpm:"unrtf~0.21.7~1.mga4", rls:"MAGEIA4"))) {
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
