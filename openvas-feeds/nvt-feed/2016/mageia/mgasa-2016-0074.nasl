# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131229");
  script_cve_id("CVE-2013-7447");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:36 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-11 16:28:51 +0000 (Fri, 11 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0074");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0074.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/10/6");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17746");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eog' package(s) announced via the MGASA-2016-0074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to a logic error, an attempt to allocate a large block of memory
fails in create_surface_from_pixbuf, leading to a crash of eog
(CVE-2013-7447).");

  script_tag(name:"affected", value:"'eog' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"eog", rpm:"eog~3.14.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eog-devel", rpm:"eog-devel~3.14.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64eog-gir3.0", rpm:"lib64eog-gir3.0~3.14.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libeog-gir3.0", rpm:"libeog-gir3.0~3.14.3~1.1.mga5", rls:"MAGEIA5"))) {
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
