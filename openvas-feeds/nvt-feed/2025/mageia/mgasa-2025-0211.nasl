# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0211");
  script_cve_id("CVE-2023-41056", "CVE-2025-27151", "CVE-2025-32023", "CVE-2025-48367");
  script_tag(name:"creation_date", value:"2025-07-21 04:25:03 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 22:28:57 +0000 (Thu, 21 Aug 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0211");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0211.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34452");
  script_xref(name:"URL", value:"https://github.com/redis/redis/releases/tag/7.2.10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the MGASA-2025-0211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated redis packages to a more recent version to fix security
vulnerabilities:
Some vulnerabilities have been discovered and fixed.
Please note this update is from 7.0 to 7.2 which brings some potentially
breaking changes. In most cases this update could be installed without
problems.
Potentially Breaking / Behavior Changes:
* Client side tracking for scripts now tracks the keys that are read by
 the script instead of the keys that are declared by the caller of EVAL /
 FCALL (#11770)
* Freeze time sampling during command execution and in scripts (#10300)
* When a blocked command is being unblocked, checks like ACL, OOM, etc
 are re-evaluated (#11012)
* Unify ACL failure error message text and error codes (#11160)
* Blocked stream command that's released when key no longer exists
 carries a different error code (#11012)
* Command stats are updated for blocked commands only when / if the
 command actually executes (#11012)
* The way ACL users are stored internally no longer removes redundant
 command and category rules, which may alter the way those rules are
 displayed as part of `ACL SAVE`, `ACL GETUSER` and `ACL LIST` (#11224)
* Client connections created for TLS-based replication use SNI if
 possible (#11458)
* Stream consumers: Re-purpose seen-time, add active-time (#11099)
* XREADGROUP and X[AUTO]CLAIM create the consumer regardless of whether
 it was able to perform some reading/claiming (#11099)
* ACL default newly created user set sanitize-payload flag in ACL
 LIST/GETUSER #11279
* Fix HELLO command not to affect the client state unless successful
 (#11659)
* Normalize `NAN` in replies to a single nan type, like we do with `inf`
 (#11597)
* Cluster SHARD IDs are no longer visible in the cluster nodes output,
 introduced in 7.2-RC1. (#10536, #12166)
* When calling PUBLISH with a RESP3 client that's also subscribed to the
 same channel, the order is changed and the reply is sent before the
 published message (#12326)");

  script_tag(name:"affected", value:"'redis' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~7.2.10~1.mga9", rls:"MAGEIA9"))) {
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
