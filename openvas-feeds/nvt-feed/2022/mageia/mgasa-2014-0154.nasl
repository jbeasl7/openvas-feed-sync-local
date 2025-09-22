# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0154");
  script_cve_id("CVE-2013-6393", "CVE-2014-2525");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0154");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0154.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2870");
  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2885");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12984");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-YAML-LibYAML' package(s) announced via the MGASA-2014-0154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated perl-YAML-LibYAML packages fix security vulnerabilities:

Florian Weimer of the Red Hat Product Security Team discovered a heap-based
buffer overflow flaw in LibYAML, a fast YAML 1.1 parser and emitter library.
A remote attacker could provide a YAML document with a specially-crafted tag
that, when parsed by an application using libyaml, would cause the application
to crash or, potentially, execute arbitrary code with the privileges of the
user running the application (CVE-2013-6393).

Ivan Fratric of the Google Security Team discovered a heap-based buffer
overflow vulnerability in LibYAML, a fast YAML 1.1 parser and emitter
library. A remote attacker could provide a specially-crafted YAML document
that, when parsed by an application using libyaml, would cause the application
to crash or, potentially, execute arbitrary code with the privileges of the
user running the application (CVE-2014-2525).

The perl-YAML-LibYAML package is being updated as it contains an embedded copy
of LibYAML.");

  script_tag(name:"affected", value:"'perl-YAML-LibYAML' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-LibYAML", rpm:"perl-YAML-LibYAML~0.380.0~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-LibYAML", rpm:"perl-YAML-LibYAML~0.410.0~2.2.mga4", rls:"MAGEIA4"))) {
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
