# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123975");
  script_cve_id("CVE-2011-4083");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0153");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0153.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos' package(s) announced via the ELSA-2012-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7-9.62.0.1.el5]
- add patch to remove all sysrq echo commands from sysreport.legacy
 (John Sobecki) [orabug 11061754]
- comment out rh-upload-core and README.rh-upload-core in specfile

[1.7-9.62]
- Always log plugin exceptions that are not raised to the interpreter
 Resolves: bz717480
- Ensure relative symlink targets are correctly handled when copying
 Resolves: bz717962
- Correctly handle libxml2 parser exceptions when reading cluster.conf
 Resolves: bz750573
- Update Red Hat Certificate System plugin for current versions
 Resolves: bz627416

[1.7-9.61]
- Make single threaded operation default and add --multithread to override
 Resolves: bz708346
- Support multiple possible locations of VRTSexplorer script
 Resolves: bz565996
- Collect wallaby dump and inventory information in mrggrid plugin
 Resolves: bz641020

[1.7-9.60]
- Add ethtool pause, coalesce and ring (-a, -c, -g) options to network plugin
 Resolves: bz726421
- Update MRG grid plugin to collect additional logs and configuration
 Resolves: bz641020

[1.7-9.59]
- Fix collection of symlink destinations when copying directory trees
 Resolves: bz717962
- Allow plugins to specify non-root symlinks for collected command output
 Resolves: bz716987
- Ensure custom rsyslog destinations are captured and log size limits applied
 Resolves: bz717167

[1.7-9.58]
- Add basic plugin for Veritas products
 Resolves: bz565996
- Do not collect subscription manager keys in general plugin
 Resolves: bz750606
- Fix gfs2 plugin use of callExtProg API
 Resolves: bz667783

[1.7-9.57]
- Fix exceptions and file naming in gfs2 plugin
 Resolves: bz667783

[1.7-9.56]
- Fix translation for fr locale
 Resolves: bz641020

[1.7-9.55]
- Add basic Infiniband plugin
 Resolves: bz673246
- Add plugin for scsi-target-utils iSCSI target
 Resolves: bz677123
- Fix handling of TMP environment variable
 Resolves: bz733133
- Correctly determine kernel version in cluster plugin
 Resolves: bz742567
- Add libvirt plugin
 Resolves: bz568635
- Add gfs2 plugin to supplement cluster data collection
 Resolves: bz667783");

  script_tag(name:"affected", value:"'sos' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"sos", rpm:"sos~1.7~9.62.0.1.el5", rls:"OracleLinux5"))) {
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
