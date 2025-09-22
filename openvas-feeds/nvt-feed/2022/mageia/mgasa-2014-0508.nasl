# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0508");
  script_cve_id("CVE-2014-9130");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0508");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0508.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14689");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1169369");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-YAML-LibYAML, yaml' package(s) announced via the MGASA-2014-0508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated yaml and perl-YAML-LibYAML packages fix security vulnerability:

An assertion failure was found in the way the libyaml library parsed wrapped
strings. An attacker able to load specially crafted YAML input into an
application using libyaml could cause the application to crash
(CVE-2014-9130).

The perl-YAML-LibYAML package is also affected, as it was derived from the
same code. Both have been patched to fix this issue.");

  script_tag(name:"affected", value:"'perl-YAML-LibYAML, yaml' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64yaml-devel", rpm:"lib64yaml-devel~0.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64yaml0_2", rpm:"lib64yaml0_2~0.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyaml-devel", rpm:"libyaml-devel~0.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyaml0_2", rpm:"libyaml0_2~0.1.6~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-LibYAML", rpm:"perl-YAML-LibYAML~0.410.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yaml", rpm:"yaml~0.1.6~1.1.mga4", rls:"MAGEIA4"))) {
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
