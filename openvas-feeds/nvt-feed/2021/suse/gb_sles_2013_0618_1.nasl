# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0618.1");
  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2274", "CVE-2013-2275");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0618-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130618-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the SUSE-SU-2013:0618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"puppet has been updated to fix 2.6.18 multiple vulnerabilities and bugs.

 * (#19391) Find the catalog for the specified node name
 * Don't assume master supports SSLv2
 * Don't require openssl client to return 0 on failure
 * Display SSL messages so we can match our regex
 * Don't assume puppetbindir is defined
 * Remove unnecessary rubygems require
 * Run openssl from windows when trying to downgrade master
 * Separate tests for same CVEs into separate files
 * Fix order-dependent test failure in rest_authconfig_spec
 * Always read request body when using Rack
 * (#19392) (CVE-2013-1653) Fix acceptance test to catch unvalidated model on 2.6
 * (#19392) (CVE-2013-1653) Validate indirection model in save handler
 * Acceptance tests for CVEs 2013 (1640, 1652, 1653,
1654, 2274, 2275)
 * (#19531) (CVE-2013-2275) Only allow report save from the node matching the certname
 * (#19391) Backport Request#remote? method
 * (#8858) Explicitly set SSL peer verification mode.
 * (#8858) Refactor tests to use real HTTP objects
 * (#19392) (CVE-2013-1653) Validate instances passed to indirector
 * (#19391) (CVE-2013-1652) Disallow use_node compiler parameter for remote requests
 * (#19151) Reject SSLv2 SSL handshakes and ciphers
 * (#14093) Restore access to the filename in the template
 * (#14093) Remove unsafe attributes from TemplateWrapper

Security Issue references:

 * CVE-2013-2275
>
 * CVE-2013-2274
>
 * CVE-2013-1655
>
 * CVE-2013-1654
>
 * CVE-2013-1653
>
 * CVE-2013-1652
>
 * CVE-2013-1640
>");

  script_tag(name:"affected", value:"'puppet' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"puppet", rpm:"puppet~2.6.18~0.4.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~2.6.18~0.4.2", rls:"SLES11.0SP2"))) {
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
