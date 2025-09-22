# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2089.1");
  script_cve_id("CVE-2011-3205", "CVE-2011-4096", "CVE-2012-5643", "CVE-2013-0188", "CVE-2013-4115", "CVE-2014-0128", "CVE-2014-6270", "CVE-2014-7141", "CVE-2014-7142", "CVE-2015-5400", "CVE-2016-2390", "CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-2572", "CVE-2016-3947", "CVE-2016-3948", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-28 13:50:33 +0000 (Thu, 28 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2089-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162089-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993299");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002212.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the SUSE-SU-2016:2089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid3 fixes the following issues:

- Multiple issues in pinger ICMP processing. (CVE-2014-7141, CVE-2014-7142)

- CVE-2016-3947: Buffer overrun issue in pinger
 ICMPv6 processing. (bsc#973782)

- CVE-2016-4554: fix header smuggling issue in HTTP Request processing (bsc#979010)

- Fix multiple Denial of Service issues in HTTP Response processing.
 (CVE-2016-2569, CVE-2016-2570, CVE-2016-2571, CVE-2016-2572,
 bsc#968392, bsc#968393, bsc#968394, bsc#968395)
- Regression caused by the DoS fixes above (bsc#993299)

- CVE-2016-3948: Fix denial of service in HTTP Response processing (bsc#973783)

- CVE-2016-4051: fixes buffer overflow in cachemgr.cgi (bsc#976553)

- CVE-2016-4052, CVE-2016-4053, CVE-2016-4054:
 * fixes multiple issues in ESI processing (bsc#976556)

- CVE-2016-4556: fixes double free vulnerability in Esi.cc (bsc#979008)

- CVE-2015-5400: Improper Protection of Alternate Path (bsc#938715)

- CVE-2014-6270: fix off-by-one in snmp subsystem (bsc#895773)

- Memory leak in squid3 when using external_acl (bsc#976708)");

  script_tag(name:"affected", value:"'squid3' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"squid3", rpm:"squid3~3.1.23~8.16.30.1", rls:"SLES11.0SP4"))) {
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
