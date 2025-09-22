# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131158");
  script_cve_id("CVE-2015-8557");
  script_tag(name:"creation_date", value:"2015-12-18 04:57:26 +0000 (Fri, 18 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-13 18:54:34 +0000 (Wed, 13 Jan 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0478");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0478.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/12/14/6");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17331");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1276321");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pygments' package(s) announced via the MGASA-2015-0478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An unsafe use of string concatenation in a shell string occurs in FontManager.
If the developer allows the attacker to choose the font and outputs an image,
the attacker can execute any shell command on the remote system. The name
variable injected comes from the constructor of FontManager, which is invoked
by ImageFormatter from options (CVE-2015-8557, rhbz#1276321).");

  script_tag(name:"affected", value:"'python-pygments' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pygments", rpm:"python-pygments~1.6~9.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pygments", rpm:"python3-pygments~1.6~9.1.mga5", rls:"MAGEIA5"))) {
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
