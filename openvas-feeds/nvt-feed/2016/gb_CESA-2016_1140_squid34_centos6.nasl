# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882498");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:20 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054",
                "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556",
                "CVE-2009-0801");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for squid34 CESA-2016:1140 centos6");
  script_tag(name:"summary", value:"Check the version of squid34");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The 'squid34' packages provide version
3.4 of Squid, a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects. Note that apart from 'squid34',
this version of Red Hat Enterprise Linux also includes the 'squid' packages
which provide Squid version 3.1.

Security Fix(es):

  * A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to execute
arbitrary code. (CVE-2016-4051)

  * Buffer overflow and input validation flaws were found in the way Squid
processed ESI responses. If Squid was used as a reverse proxy, or for
TLS/HTTPS interception, a remote attacker able to control ESI components on
an HTTP server could use these flaws to crash Squid, disclose parts of the
stack memory, or possibly execute arbitrary code as the user running Squid.
(CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  * An input validation flaw was found in the way Squid handled intercepted
HTTP Request messages. An attacker could use this flaw to bypass the
protection against issues related to CVE-2009-0801, and perform cache
poisoning attacks on Squid. (CVE-2016-4553)

  * An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with specially
crafted header Host header that bypasses same-origin security protections,
causing Squid operating as interception or reverse-proxy to contact the
wrong origin server. It could also be used for cache poisoning for client
not following RFC 7230. (CVE-2016-4554)

  * A NULL pointer dereference flaw was found in the way Squid processes ESI
responses. If Squid was used as a reverse proxy or for TLS/HTTPS
interception, a malicious server could use this flaw to crash the Squid
worker process. (CVE-2016-4555)

  * An incorrect reference counting flaw was found in the way Squid processes
ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS
interception, an attacker controlling a server accessed by Squid, could
crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)");
  script_tag(name:"affected", value:"squid34 on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1140");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021897.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"squid34", rpm:"squid34~3.4.14~9.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
