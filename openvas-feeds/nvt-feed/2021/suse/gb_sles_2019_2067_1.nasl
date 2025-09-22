# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2067.1");
  script_cve_id("CVE-2019-3685");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 16:35:09 +0000 (Fri, 08 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2067-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192067-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'osc' package(s) announced via the SUSE-SU-2019:2067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for osc to version 0.165.4 fixes the following issues:

Security issue fixed:
CVE-2019-3685: Fixed broken TLS certificate handling allowing for a
 Man-in-the-middle attack (bsc#1142518).

Non-security issues fixed:
support different token operations (runservice, release and rebuild)
 (requires OBS 2.10)

fix osc token decode error

offline build mode is now really offline and does not try to download
 the buildconfig

osc build -define now works with python3

fixes an issue where the error message on osc meta -e was not parsed
 correctly

osc maintainer -s now works with python3

simplified and fixed osc meta -e (bsc#1138977)

osc lbl now works with non utf8 encoding (bsc#1129889)

add simpleimage as local build type

allow optional fork when creating a maintenance request

fix RPMError fallback

fix local caching for all package formats

fix appname for trusted cert store

osc -h does not break anymore when using plugins

switch to difflib.diff_bytes and sys.stdout.buffer.write for diffing.
 This will fix all decoding issues with osc diff, osc ci and osc rq -d

fix osc ls -lb handling empty size and mtime

removed decoding on osc api command.");

  script_tag(name:"affected", value:"'osc' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"osc", rpm:"osc~0.165.4~3.9.1", rls:"SLES15.0SP1"))) {
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
