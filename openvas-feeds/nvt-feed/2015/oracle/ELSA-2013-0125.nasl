# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123763");
  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0125");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0125.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the ELSA-2013-0125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.15-5.0.1.el5]
- Added oracle-ocfs2-network.patch
- increase max packet size to 65536 (Herbert van den Bergh) [orabug 13542633]

[1.0.15-5]
- fixed CVE-2012-4285, CVE-2012-4289, CVE-2012-4291 and CVE-2012-4290
 (#849521)

[1.0.15-4]
- fixed NetDump dissector (#484999)

[1.0.15-3]
- fixed various flaws: CVE-2011-1959 CVE-2011-2175 CVE-2011-1958
 CVE-2011-2698 CVE-2011-4102 CVE-2012-0041 CVE-2012-0042 CVE-2012-0066
 CVE-2012-0067

[1.0.15-2]
- fixed tshark -s option (#580513)
- fixed tshark exit code when dumpcap fails (#580510)
- fixed editing of columns in Wireshark preferences (#493693)
- added netdump protocol dissector (#484999)
- fixed tshark / Wireshark automatic filter when started in ssh connection
 over IPv6 (#438473)");

  script_tag(name:"affected", value:"'wireshark' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~5.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.15~5.0.1.el5", rls:"OracleLinux5"))) {
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
