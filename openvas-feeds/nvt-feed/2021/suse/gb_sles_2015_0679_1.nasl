# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0679.1");
  script_cve_id("CVE-2014-9140", "CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0679-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0679-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150679-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923142");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001335.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2015:0679-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tcpdump was updated to fix five vulnerabilities in protocol printers

When running tcpdump, a remote unauthenticated user could have crashed the application or, potentially, execute arbitrary code by injecting crafted packages into the network.

The following vulnerabilities were fixed:
 * IPv6 mobility printer remote DoS (CVE-2015-0261, bnc#922220)
 * PPP printer remote DoS (CVE-2014-9140, bnc#923142)
 * force printer remote DoS (CVE-2015-2155, bnc#922223)
 * ethernet printer remote DoS (CVE-2015-2154, bnc#922222)
 * tcp printer remote DoS (CVE-2015-2153, bnc#922221)");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.5.1~7.1", rls:"SLES12.0"))) {
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
