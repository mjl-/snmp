implement SnmpGet;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "snmp.m";
	snmp: Snmp;
	Val: import snmp;
include "snmpclient.m";
	snmpclient: Snmpclient;
	Snmpc: import snmpclient;

SnmpGet: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


dflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	snmp = load Snmp Snmp->PATH;
	snmp->init();
	snmpclient = load Snmpclient Snmpclient->PATH;
	snmpclient->init();

	s := Snmpc.new();
	arg->init(args);
	arg->setusage(arg->progname()+" [-d] "+snmpclient->usage+" addr oid ...");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	snmp->dflag = dflag++;
		* =>	s.setopt(c, arg);
		}
	args = arg->argv();
	if(len args < 2)
		arg->usage();
	s.addr = hd args;
	args = tl args;

	l: list of ref (string, ref Val);
	err := s.init();
	if(err == nil)
		(l, err) = s.getm(args);
	if(err != nil)
		fail("get: "+err);
	for(; l != nil; l = tl l) {
		(o, v) := *hd l;
		sys->print("%-35s %s\n", o, v.text());
	}
}

fail(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
	raise "fail:"+s;
}
