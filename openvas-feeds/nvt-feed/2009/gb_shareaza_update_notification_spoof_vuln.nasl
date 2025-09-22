# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800604");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7164");
  script_name("Shareaza Update Notification Spoofing Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_shareaza_detect.nasl");
  script_require_ports("Services/www", 6346);
  script_mandatory_keys("shareaza/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers conduct spoofing attacks.");

  script_tag(name:"affected", value:"Shareaza prior to version 2.3.1.0.");

  script_tag(name:"insight", value:"The flaw is due to update notifications being handled via the domain
  update.shareaza.com, which is no longer controlled by the vendor. This can
  be exploited to spoof update notifications.");

  script_tag(name:"solution", value:"Upgrade Shareaza to version 2.3.1.0.");

  script_tag(name:"summary", value:"Shareaza is prone to an update notification spoofing vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27171");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/39484");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?group_id=110672&release_id=565250");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

shareazaPort = http_get_port(default:6346);

shareazaVer = get_kb_item("www/" + shareazaPort + "/Shareaza");

if(shareazaVer != NULL)
{
  if(version_is_less(version:shareazaVer, test_version:"2.3.1.0")){
    report = report_fixed_ver(installed_version:shareazaVer, fixed_version:"2.3.1.0");
    security_message(port: shareazaPort, data: report);
    exit(0);
  }
}

exit(99);
