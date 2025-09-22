# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131271");
  script_cve_id("CVE-2016-2563");
  script_tag(name:"creation_date", value:"2016-03-17 14:02:33 +0000 (Thu, 17 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-08 17:41:23 +0000 (Fri, 08 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0112");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0112.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-pscp-sink-sscanf.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17942");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'halibut, putty' package(s) announced via the MGASA-2016-0112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated putty package fixes security vulnerability:

Many versions of PSCP in PuTTY prior to 0.67 have a stack corruption
vulnerability in their treatment of the 'sink' direction (i.e. downloading
from server to client) of the old-style SCP protocol. In order for this
vulnerability to be exploited, the user must connect to a malicious server
and attempt to download any file (CVE-2016-2563).

The putty package has been updated to version 0.67 to fix this issue and a
few other bugs. The halibut package has been updated to version 1.1 to build
the documentation.");

  script_tag(name:"affected", value:"'halibut, putty' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"halibut", rpm:"halibut~1.1~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.67~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-halibut", rpm:"vim-halibut~1.1~2.mga5", rls:"MAGEIA5"))) {
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
