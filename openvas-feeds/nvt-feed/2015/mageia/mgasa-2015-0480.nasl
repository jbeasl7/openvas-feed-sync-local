# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131160");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"creation_date", value:"2015-12-21 12:43:01 +0000 (Mon, 21 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0480");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0480.html");
  script_xref(name:"URL", value:"http://hmarco.org/bugs/CVE-2015-8370-Grub2-authentication-bypass.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17334");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-2623.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the MGASA-2015-0480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the grub2 handled backspace characters entered
in username and password prompts. An attacker with access to the system
console could use this flaw to bypass grub2 password protection and gain
administrative access to the system (CVE-2015-8370).");

  script_tag(name:"affected", value:"'grub2' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.git9752.18.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.02~0.git9752.18.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-mageia-theme", rpm:"grub2-mageia-theme~2.02~0.git9752.18.3.mga5", rls:"MAGEIA5"))) {
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
