# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122883");
  script_cve_id("CVE-2015-7529");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:23 +0000 (Thu, 18 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 15:52:00 +0000 (Fri, 27 Sep 2019)");

  script_name("Oracle: Security Advisory (ELSA-2016-0188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0188");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0188.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos' package(s) announced via the ELSA-2016-0188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.2-35.0.1.3]
- Recreated patch for [orabug 18913115]
- Make the selinux plugin fixfiles option useful (John Haxby) [orabug 18913115]
- Added remove_gpgstring.patch [Bug 18313898]
- Added sos-oracle-enterprise.patch
- Added sos-oraclelinux-vendor-vendorurl.patch

[= 3.2-37]
- [sosreport] prepare report in a private subdirectory (updated)
 Resolves: bz1290954

[= 3.2-35.2]
- [sosreport] prepare report in a private subdirectory (updated)
 Resolves: bz1290954

[= 3.2-35.1]
- [ceph] collect /var/lib/ceph and /var/run/ceph
 Resolves: bz1291347
- [sosreport] prepare report in a private subdirectory
 Resolves: bz1290954");

  script_tag(name:"affected", value:"'sos' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"sos", rpm:"sos~3.2~35.0.1.el7_2.3", rls:"OracleLinux7"))) {
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
