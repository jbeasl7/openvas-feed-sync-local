# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0422");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0422)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0422");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0422.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/10/24/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17013");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exfat-utils' package(s) announced via the MGASA-2015-0422 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix heap overflow and endless loop in exfatfsck

exfat-utils is a collection of tools to work with the exFAT filesystem.
Fuzzing the exfatfsck with american fuzzy lop led to the discovery of a
write heap overflow and an endless loop.

Especially at risk are systems that are configured to run filesystem
checks automatically on external devices like USB flash drives.

A malformed input can cause a write heap overflow in the function
verify_vbr_checksum. It might be possible to use this for code
execution.

Another malformed input can cause an endless loop, leading to a
possible denial of service.");

  script_tag(name:"affected", value:"'exfat-utils' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"exfat-utils", rpm:"exfat-utils~1.1.0~3.1.mga5", rls:"MAGEIA5"))) {
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
