# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122875");
  script_cve_id("CVE-2015-7529");
  script_tag(name:"creation_date", value:"2016-02-11 05:20:46 +0000 (Thu, 11 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 15:52:00 +0000 (Fri, 27 Sep 2019)");

  script_name("Oracle: Security Advisory (ELSA-2016-0152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0152");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0152.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos' package(s) announced via the ELSA-2016-0152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.2-28.0.1.2]
- Add vendor, vendor URL info for Oracle Linux [orabug 17656507] (joe.jin@oracle.com)
- Direct traceroute to linux.oracle.com (John Haxby) [orabug 11713272] (joe.jin@oracle.com)
- Check oraclelinux-release instead of redhat-release to get OS version (John Haxby) [bug 11681869] (joe.jin@oracle.com)
- Remove RH ftp URL and support email (joe.jin@oracle.com)
- add sos-oracle-enterprise.patch (joe.jin@oracle.com)
- Add smartmon plugin (John Haxby) [orabug 17995005] (joe.jin@oracle.com)

[= 3.2-28.el6_7.2]
- [sosreport] Report correct final path with --build
 Related: bz1290953

[= 3.2-28.el6_7.1]
- [hpasm] Add timeout.
 Resolves: bz1291828

[= 3.2-28.el6_7]
- [sosreport] Prepare report in a private subdirectory
 Resolves: bz1290953");

  script_tag(name:"affected", value:"'sos' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sos", rpm:"sos~3.2~28.0.1.el6_7.2", rls:"OracleLinux6"))) {
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
