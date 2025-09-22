# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131289");
  script_cve_id("CVE-2016-3096");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:52 +0000 (Mon, 09 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-06 19:26:11 +0000 (Mon, 06 Jun 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0163");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0163.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18275");
  script_xref(name:"URL", value:"https://github.com/ansible/ansible/blob/stable-1.9/CHANGELOG.md");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-April/183132.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible' package(s) announced via the MGASA-2016-0163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ansible package fixes security vulnerability:

A vulnerability in lxc_container, ansible module, was found allowing to get
root inside the container. The problem is in the create_script function, which
tries to write to /opt/.lxc-attach-script inside of the container. If the
attacker can write to /opt/.lxc-attach-script before that, he can overwrite
arbitrary files or execute commands as root (CVE-2016-3096).");

  script_tag(name:"affected", value:"'ansible' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~1.9.6~1.mga5", rls:"MAGEIA5"))) {
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
