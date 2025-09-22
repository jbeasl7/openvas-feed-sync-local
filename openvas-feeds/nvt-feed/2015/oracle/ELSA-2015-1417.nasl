# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123059");
  script_cve_id("CVE-2002-0389", "CVE-2015-2775");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1417");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1417.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman' package(s) announced via the ELSA-2015-1417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3:2.1.12-25]
- fix CVE-2002-0389 - local users able to read private mailing list archives

[3:2.1.12-24]
- fix CVE-2015-2775 - directory traversal in MTA transports

[3:2.1.12-23]
- fix #1095359 - handle update when some mailing lists have been created
 by newer Mailman than this one

[3:2.1.12-22]
- fix #1095359 - add support for DMARC

[3:2.1.12-21]
- fix #1056366 - fix bad subject of the welcome email when creating list using
 newlist command

[3:2.1.12-20]
- fix #745409 - do not set Indexes in httpd configuration for public archive
- fix #1008139 - fix traceback when list_data_dir is not a child of var_prefix

[3:2.1.12-19]
- fix #765807 - fix traceback when message is received to moderated list");

  script_tag(name:"affected", value:"'mailman' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.12~25.el6", rls:"OracleLinux6"))) {
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
