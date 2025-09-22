# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0010");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0010");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0010.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/12/24/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12100");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1046113");
  script_xref(name:"URL", value:"https://secunia.com/advisories/55976/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios' package(s) announced via the MGASA-2014-0010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was reported and fixed in Nagios, which can be exploited to cause a
denial of service. This vulnerability is caused due to an off-by-one
error within the process_cgivars() function, which can be exploited to
cause an out-of-bounds read by sending a specially-crafted key value to the Nagios
web UI (CVE-2013-7108, CVE-2013-7205).
An issue that prevented the service from starting has also been fixed.");

  script_tag(name:"affected", value:"'nagios' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"nagios", rpm:"nagios~3.4.4~4.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-devel", rpm:"nagios-devel~3.4.4~4.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-www", rpm:"nagios-www~3.4.4~4.2.mga3", rls:"MAGEIA3"))) {
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
